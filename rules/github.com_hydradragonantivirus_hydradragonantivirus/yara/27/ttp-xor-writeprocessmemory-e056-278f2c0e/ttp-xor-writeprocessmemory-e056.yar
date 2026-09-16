rule TTP_XOR_WriteProcessMemory_e056 {
  strings:
    $key_e056 = { b7 24 [2] 85 06 [2] 83 33 [2] ad 33 [2] 92 2f }

  condition:
    any of them
}