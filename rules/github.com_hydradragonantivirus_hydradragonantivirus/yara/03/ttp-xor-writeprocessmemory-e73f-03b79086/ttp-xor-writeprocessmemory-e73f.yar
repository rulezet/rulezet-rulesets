rule TTP_XOR_WriteProcessMemory_e73f {
  strings:
    $key_e73f = { b0 4d [2] 82 6f [2] 84 5a [2] aa 5a [2] 95 46 }

  condition:
    any of them
}