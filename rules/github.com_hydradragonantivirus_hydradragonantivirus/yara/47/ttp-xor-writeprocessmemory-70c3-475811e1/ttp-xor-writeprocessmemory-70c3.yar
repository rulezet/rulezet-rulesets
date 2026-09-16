rule TTP_XOR_WriteProcessMemory_70c3 {
  strings:
    $key_70c3 = { 27 b1 [2] 15 93 [2] 13 a6 [2] 3d a6 [2] 02 ba }

  condition:
    any of them
}