rule TTP_XOR_WriteProcessMemory_55d3 {
  strings:
    $key_55d3 = { 02 a1 [2] 30 83 [2] 36 b6 [2] 18 b6 [2] 27 aa }

  condition:
    any of them
}