rule TTP_XOR_WriteProcessMemory_e70f {
  strings:
    $key_e70f = { b0 7d [2] 82 5f [2] 84 6a [2] aa 6a [2] 95 76 }

  condition:
    any of them
}