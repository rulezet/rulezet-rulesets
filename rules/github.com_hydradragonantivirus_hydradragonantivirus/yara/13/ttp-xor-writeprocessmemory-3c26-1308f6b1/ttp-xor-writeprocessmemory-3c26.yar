rule TTP_XOR_WriteProcessMemory_3c26 {
  strings:
    $key_3c26 = { 6b 54 [2] 59 76 [2] 5f 43 [2] 71 43 [2] 4e 5f }

  condition:
    any of them
}