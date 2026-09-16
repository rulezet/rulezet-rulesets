rule TTP_XOR_WriteProcessMemory_6f71 {
  strings:
    $key_6f71 = { 38 03 [2] 0a 21 [2] 0c 14 [2] 22 14 [2] 1d 08 }

  condition:
    any of them
}