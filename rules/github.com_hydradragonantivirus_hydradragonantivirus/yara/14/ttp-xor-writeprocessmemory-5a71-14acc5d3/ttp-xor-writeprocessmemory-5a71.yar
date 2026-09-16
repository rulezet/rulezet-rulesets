rule TTP_XOR_WriteProcessMemory_5a71 {
  strings:
    $key_5a71 = { 0d 03 [2] 3f 21 [2] 39 14 [2] 17 14 [2] 28 08 }

  condition:
    any of them
}