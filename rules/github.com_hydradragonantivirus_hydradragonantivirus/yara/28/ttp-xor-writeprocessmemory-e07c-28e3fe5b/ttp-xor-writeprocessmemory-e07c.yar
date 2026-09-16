rule TTP_XOR_WriteProcessMemory_e07c {
  strings:
    $key_e07c = { b7 0e [2] 85 2c [2] 83 19 [2] ad 19 [2] 92 05 }

  condition:
    any of them
}