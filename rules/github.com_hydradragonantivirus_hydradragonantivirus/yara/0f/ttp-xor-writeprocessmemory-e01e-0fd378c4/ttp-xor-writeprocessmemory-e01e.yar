rule TTP_XOR_WriteProcessMemory_e01e {
  strings:
    $key_e01e = { b7 6c [2] 85 4e [2] 83 7b [2] ad 7b [2] 92 67 }

  condition:
    any of them
}