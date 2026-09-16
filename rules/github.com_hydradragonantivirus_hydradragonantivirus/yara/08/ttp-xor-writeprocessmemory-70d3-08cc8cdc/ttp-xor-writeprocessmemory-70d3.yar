rule TTP_XOR_WriteProcessMemory_70d3 {
  strings:
    $key_70d3 = { 27 a1 [2] 15 83 [2] 13 b6 [2] 3d b6 [2] 02 aa }

  condition:
    any of them
}