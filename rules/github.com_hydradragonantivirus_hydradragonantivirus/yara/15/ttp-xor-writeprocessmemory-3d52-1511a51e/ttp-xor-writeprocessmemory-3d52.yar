rule TTP_XOR_WriteProcessMemory_3d52 {
  strings:
    $key_3d52 = { 6a 20 [2] 58 02 [2] 5e 37 [2] 70 37 [2] 4f 2b }

  condition:
    any of them
}