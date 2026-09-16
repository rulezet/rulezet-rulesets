rule TTP_XOR_WriteProcessMemory_3c03 {
  strings:
    $key_3c03 = { 6b 71 [2] 59 53 [2] 5f 66 [2] 71 66 [2] 4e 7a }

  condition:
    any of them
}