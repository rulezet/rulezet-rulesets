rule TTP_XOR_WriteProcessMemory_e7ff {
  strings:
    $key_e7ff = { b0 8d [2] 82 af [2] 84 9a [2] aa 9a [2] 95 86 }

  condition:
    any of them
}