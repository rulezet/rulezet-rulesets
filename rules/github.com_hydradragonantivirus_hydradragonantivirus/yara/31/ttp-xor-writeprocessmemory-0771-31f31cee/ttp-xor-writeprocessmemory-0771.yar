rule TTP_XOR_WriteProcessMemory_0771 {
  strings:
    $key_0771 = { 50 03 [2] 62 21 [2] 64 14 [2] 4a 14 [2] 75 08 }

  condition:
    any of them
}