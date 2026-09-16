rule TTP_XOR_WriteProcessMemory_5d71 {
  strings:
    $key_5d71 = { 0a 03 [2] 38 21 [2] 3e 14 [2] 10 14 [2] 2f 08 }

  condition:
    any of them
}