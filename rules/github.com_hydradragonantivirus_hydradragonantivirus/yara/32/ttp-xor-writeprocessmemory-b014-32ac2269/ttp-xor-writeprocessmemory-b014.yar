rule TTP_XOR_WriteProcessMemory_b014 {
  strings:
    $key_b014 = { e7 66 [2] d5 44 [2] d3 71 [2] fd 71 [2] c2 6d }

  condition:
    any of them
}