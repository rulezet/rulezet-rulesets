rule TTP_XOR_WriteProcessMemory_9980 {
  strings:
    $key_9980 = { ce f2 [2] fc d0 [2] fa e5 [2] d4 e5 [2] eb f9 }

  condition:
    any of them
}