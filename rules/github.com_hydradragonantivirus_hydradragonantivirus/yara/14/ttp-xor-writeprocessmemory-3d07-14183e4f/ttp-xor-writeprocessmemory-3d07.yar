rule TTP_XOR_WriteProcessMemory_3d07 {
  strings:
    $key_3d07 = { 6a 75 [2] 58 57 [2] 5e 62 [2] 70 62 [2] 4f 7e }

  condition:
    any of them
}