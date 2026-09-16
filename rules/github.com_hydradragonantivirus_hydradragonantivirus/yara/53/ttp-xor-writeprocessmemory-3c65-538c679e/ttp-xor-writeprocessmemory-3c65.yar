rule TTP_XOR_WriteProcessMemory_3c65 {
  strings:
    $key_3c65 = { 6b 17 [2] 59 35 [2] 5f 00 [2] 71 00 [2] 4e 1c }

  condition:
    any of them
}