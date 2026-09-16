rule TTP_XOR_WriteProcessMemory_40d3 {
  strings:
    $key_40d3 = { 17 a1 [2] 25 83 [2] 23 b6 [2] 0d b6 [2] 32 aa }

  condition:
    any of them
}