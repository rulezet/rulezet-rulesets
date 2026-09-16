rule TTP_XOR_WriteProcessMemory_56d3 {
  strings:
    $key_56d3 = { 01 a1 [2] 33 83 [2] 35 b6 [2] 1b b6 [2] 24 aa }

  condition:
    any of them
}