rule TTP_XOR_WriteProcessMemory_e0ff {
  strings:
    $key_e0ff = { b7 8d [2] 85 af [2] 83 9a [2] ad 9a [2] 92 86 }

  condition:
    any of them
}