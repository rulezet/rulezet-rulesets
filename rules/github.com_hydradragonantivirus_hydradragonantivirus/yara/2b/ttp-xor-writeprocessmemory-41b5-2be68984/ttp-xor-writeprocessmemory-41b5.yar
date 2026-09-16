rule TTP_XOR_WriteProcessMemory_41b5 {
  strings:
    $key_41b5 = { 16 c7 [2] 24 e5 [2] 22 d0 [2] 0c d0 [2] 33 cc }

  condition:
    any of them
}