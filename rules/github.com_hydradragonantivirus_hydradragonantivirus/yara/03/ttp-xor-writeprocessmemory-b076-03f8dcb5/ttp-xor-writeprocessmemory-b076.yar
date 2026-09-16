rule TTP_XOR_WriteProcessMemory_b076 {
  strings:
    $key_b076 = { e7 04 [2] d5 26 [2] d3 13 [2] fd 13 [2] c2 0f }

  condition:
    any of them
}