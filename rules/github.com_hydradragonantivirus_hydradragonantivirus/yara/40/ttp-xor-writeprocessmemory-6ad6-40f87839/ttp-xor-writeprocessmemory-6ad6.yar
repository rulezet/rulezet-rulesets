rule TTP_XOR_WriteProcessMemory_6ad6 {
  strings:
    $key_6ad6 = { 3d a4 [2] 0f 86 [2] 09 b3 [2] 27 b3 [2] 18 af }

  condition:
    any of them
}