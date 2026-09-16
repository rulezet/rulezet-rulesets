rule TTP_XOR_WriteProcessMemory_50d3 {
  strings:
    $key_50d3 = { 07 a1 [2] 35 83 [2] 33 b6 [2] 1d b6 [2] 22 aa }

  condition:
    any of them
}