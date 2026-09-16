rule TTP_XOR_WriteProcessMemory_e72c {
  strings:
    $key_e72c = { b0 5e [2] 82 7c [2] 84 49 [2] aa 49 [2] 95 55 }

  condition:
    any of them
}