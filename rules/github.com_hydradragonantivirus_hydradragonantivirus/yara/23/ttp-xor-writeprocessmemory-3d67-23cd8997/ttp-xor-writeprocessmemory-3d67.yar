rule TTP_XOR_WriteProcessMemory_3d67 {
  strings:
    $key_3d67 = { 6a 15 [2] 58 37 [2] 5e 02 [2] 70 02 [2] 4f 1e }

  condition:
    any of them
}