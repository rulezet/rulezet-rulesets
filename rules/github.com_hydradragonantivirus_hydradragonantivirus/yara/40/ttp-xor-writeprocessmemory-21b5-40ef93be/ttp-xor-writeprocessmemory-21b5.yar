rule TTP_XOR_WriteProcessMemory_21b5 {
  strings:
    $key_21b5 = { 76 c7 [2] 44 e5 [2] 42 d0 [2] 6c d0 [2] 53 cc }

  condition:
    any of them
}