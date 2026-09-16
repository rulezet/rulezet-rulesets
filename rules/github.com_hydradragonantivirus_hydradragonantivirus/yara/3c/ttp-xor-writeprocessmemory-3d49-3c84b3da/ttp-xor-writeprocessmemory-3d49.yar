rule TTP_XOR_WriteProcessMemory_3d49 {
  strings:
    $key_3d49 = { 6a 3b [2] 58 19 [2] 5e 2c [2] 70 2c [2] 4f 30 }

  condition:
    any of them
}