rule TTP_XOR_WriteProcessMemory_9989 {
  strings:
    $key_9989 = { ce fb [2] fc d9 [2] fa ec [2] d4 ec [2] eb f0 }

  condition:
    any of them
}