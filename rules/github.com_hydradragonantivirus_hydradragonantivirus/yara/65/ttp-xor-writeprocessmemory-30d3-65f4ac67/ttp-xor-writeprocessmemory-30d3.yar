rule TTP_XOR_WriteProcessMemory_30d3 {
  strings:
    $key_30d3 = { 67 a1 [2] 55 83 [2] 53 b6 [2] 7d b6 [2] 42 aa }

  condition:
    any of them
}