rule TTP_XOR_WriteProcessMemory_a176 {
  strings:
    $key_a176 = { f6 04 [2] c4 26 [2] c2 13 [2] ec 13 [2] d3 0f }

  condition:
    any of them
}