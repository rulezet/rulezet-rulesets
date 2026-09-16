rule TTP_XOR_WriteProcessMemory_e05c {
  strings:
    $key_e05c = { b7 2e [2] 85 0c [2] 83 39 [2] ad 39 [2] 92 25 }

  condition:
    any of them
}