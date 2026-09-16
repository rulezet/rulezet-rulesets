rule TTP_XOR_WriteProcessMemory_b064 {
  strings:
    $key_b064 = { e7 16 [2] d5 34 [2] d3 01 [2] fd 01 [2] c2 1d }

  condition:
    any of them
}