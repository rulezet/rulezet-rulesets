rule TTP_XOR_WriteProcessMemory_ef6b {
  strings:
    $key_ef6b = { b8 19 [2] 8a 3b [2] 8c 0e [2] a2 0e [2] 9d 12 }

  condition:
    any of them
}