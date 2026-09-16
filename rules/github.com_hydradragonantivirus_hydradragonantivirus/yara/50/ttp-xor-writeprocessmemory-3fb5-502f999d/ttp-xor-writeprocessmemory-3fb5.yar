rule TTP_XOR_WriteProcessMemory_3fb5 {
  strings:
    $key_3fb5 = { 68 c7 [2] 5a e5 [2] 5c d0 [2] 72 d0 [2] 4d cc }

  condition:
    any of them
}