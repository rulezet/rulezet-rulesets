rule TTP_XOR_WriteProcessMemory_70c2 {
  strings:
    $key_70c2 = { 27 b0 [2] 15 92 [2] 13 a7 [2] 3d a7 [2] 02 bb }

  condition:
    any of them
}