rule TTP_XOR_WriteProcessMemory_f631 {
  strings:
    $key_f631 = { a1 43 [2] 93 61 [2] 95 54 [2] bb 54 [2] 84 48 }

  condition:
    any of them
}