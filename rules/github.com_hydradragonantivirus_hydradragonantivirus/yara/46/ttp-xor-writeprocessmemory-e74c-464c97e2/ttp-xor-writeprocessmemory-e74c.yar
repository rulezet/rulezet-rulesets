rule TTP_XOR_WriteProcessMemory_e74c {
  strings:
    $key_e74c = { b0 3e [2] 82 1c [2] 84 29 [2] aa 29 [2] 95 35 }

  condition:
    any of them
}