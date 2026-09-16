rule TTP_XOR_WriteProcessMemory_42d3 {
  strings:
    $key_42d3 = { 15 a1 [2] 27 83 [2] 21 b6 [2] 0f b6 [2] 30 aa }

  condition:
    any of them
}