rule TTP_XOR_WriteProcessMemory_3c71 {
  strings:
    $key_3c71 = { 6b 03 [2] 59 21 [2] 5f 14 [2] 71 14 [2] 4e 08 }

  condition:
    any of them
}