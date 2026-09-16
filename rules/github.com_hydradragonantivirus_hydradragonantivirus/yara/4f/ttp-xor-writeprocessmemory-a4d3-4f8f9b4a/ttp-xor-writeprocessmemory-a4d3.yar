rule TTP_XOR_WriteProcessMemory_a4d3 {
  strings:
    $key_a4d3 = { f3 a1 [2] c1 83 [2] c7 b6 [2] e9 b6 [2] d6 aa }

  condition:
    any of them
}