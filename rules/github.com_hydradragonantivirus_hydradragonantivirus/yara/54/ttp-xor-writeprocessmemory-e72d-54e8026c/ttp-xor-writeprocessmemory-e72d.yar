rule TTP_XOR_WriteProcessMemory_e72d {
  strings:
    $key_e72d = { b0 5f [2] 82 7d [2] 84 48 [2] aa 48 [2] 95 54 }

  condition:
    any of them
}