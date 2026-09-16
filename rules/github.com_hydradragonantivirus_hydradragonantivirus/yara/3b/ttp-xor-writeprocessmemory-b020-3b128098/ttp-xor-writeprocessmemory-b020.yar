rule TTP_XOR_WriteProcessMemory_b020 {
  strings:
    $key_b020 = { e7 52 [2] d5 70 [2] d3 45 [2] fd 45 [2] c2 59 }

  condition:
    any of them
}