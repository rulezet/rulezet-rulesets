rule TTP_XOR_WriteProcessMemory_e05d {
  strings:
    $key_e05d = { b7 2f [2] 85 0d [2] 83 38 [2] ad 38 [2] 92 24 }

  condition:
    any of them
}