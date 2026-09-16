rule TTP_XOR_WriteProcessMemory_0f71 {
  strings:
    $key_0f71 = { 58 03 [2] 6a 21 [2] 6c 14 [2] 42 14 [2] 7d 08 }

  condition:
    any of them
}