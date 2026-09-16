rule TTP_XOR_WriteProcessMemory_e74d {
  strings:
    $key_e74d = { b0 3f [2] 82 1d [2] 84 28 [2] aa 28 [2] 95 34 }

  condition:
    any of them
}