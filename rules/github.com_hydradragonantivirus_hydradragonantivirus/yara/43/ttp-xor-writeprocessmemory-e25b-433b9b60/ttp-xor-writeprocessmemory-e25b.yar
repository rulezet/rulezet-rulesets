rule TTP_XOR_WriteProcessMemory_e25b {
  strings:
    $key_e25b = { b5 29 [2] 87 0b [2] 81 3e [2] af 3e [2] 90 22 }

  condition:
    any of them
}