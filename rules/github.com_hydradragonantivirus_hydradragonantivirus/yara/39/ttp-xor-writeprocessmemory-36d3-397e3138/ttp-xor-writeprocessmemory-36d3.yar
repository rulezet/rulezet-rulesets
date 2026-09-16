rule TTP_XOR_WriteProcessMemory_36d3 {
  strings:
    $key_36d3 = { 61 a1 [2] 53 83 [2] 55 b6 [2] 7b b6 [2] 44 aa }

  condition:
    any of them
}