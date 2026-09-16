rule TTP_XOR_WriteProcessMemory_ef7b {
  strings:
    $key_ef7b = { b8 09 [2] 8a 2b [2] 8c 1e [2] a2 1e [2] 9d 02 }

  condition:
    any of them
}