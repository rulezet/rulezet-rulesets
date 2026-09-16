rule TTP_XOR_WriteProcessMemory_3d70 {
  strings:
    $key_3d70 = { 6a 02 [2] 58 20 [2] 5e 15 [2] 70 15 [2] 4f 09 }

  condition:
    any of them
}