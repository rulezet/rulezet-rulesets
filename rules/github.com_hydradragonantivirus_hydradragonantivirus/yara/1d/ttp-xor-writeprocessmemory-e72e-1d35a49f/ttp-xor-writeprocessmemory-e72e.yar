rule TTP_XOR_WriteProcessMemory_e72e {
  strings:
    $key_e72e = { b0 5c [2] 82 7e [2] 84 4b [2] aa 4b [2] 95 57 }

  condition:
    any of them
}