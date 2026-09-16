rule TTP_XOR_WriteProcessMemory_72d3 {
  strings:
    $key_72d3 = { 25 a1 [2] 17 83 [2] 11 b6 [2] 3f b6 [2] 00 aa }

  condition:
    any of them
}