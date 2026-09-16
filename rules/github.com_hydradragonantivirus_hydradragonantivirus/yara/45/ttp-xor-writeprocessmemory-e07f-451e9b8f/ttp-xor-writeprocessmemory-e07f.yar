rule TTP_XOR_WriteProcessMemory_e07f {
  strings:
    $key_e07f = { b7 0d [2] 85 2f [2] 83 1a [2] ad 1a [2] 92 06 }

  condition:
    any of them
}