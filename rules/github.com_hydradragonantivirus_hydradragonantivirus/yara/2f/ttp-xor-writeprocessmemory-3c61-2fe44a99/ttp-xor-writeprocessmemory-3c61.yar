rule TTP_XOR_WriteProcessMemory_3c61 {
  strings:
    $key_3c61 = { 6b 13 [2] 59 31 [2] 5f 04 [2] 71 04 [2] 4e 18 }

  condition:
    any of them
}