rule TTP_XOR_WriteProcessMemory_b049 {
  strings:
    $key_b049 = { e7 3b [2] d5 19 [2] d3 2c [2] fd 2c [2] c2 30 }

  condition:
    any of them
}