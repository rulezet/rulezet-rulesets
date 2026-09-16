rule TTP_XOR_WriteProcessMemory_ef3b {
  strings:
    $key_ef3b = { b8 49 [2] 8a 6b [2] 8c 5e [2] a2 5e [2] 9d 42 }

  condition:
    any of them
}