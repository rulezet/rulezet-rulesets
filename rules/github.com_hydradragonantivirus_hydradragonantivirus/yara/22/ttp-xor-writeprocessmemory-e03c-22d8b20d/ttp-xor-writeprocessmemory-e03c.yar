rule TTP_XOR_WriteProcessMemory_e03c {
  strings:
    $key_e03c = { b7 4e [2] 85 6c [2] 83 59 [2] ad 59 [2] 92 45 }

  condition:
    any of them
}