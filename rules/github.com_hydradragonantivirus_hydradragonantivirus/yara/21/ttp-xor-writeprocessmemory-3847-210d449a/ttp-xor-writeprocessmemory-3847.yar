rule TTP_XOR_WriteProcessMemory_3847 {
  strings:
    $key_3847 = { 6f 35 [2] 5d 17 [2] 5b 22 [2] 75 22 [2] 4a 3e }

  condition:
    any of them
}