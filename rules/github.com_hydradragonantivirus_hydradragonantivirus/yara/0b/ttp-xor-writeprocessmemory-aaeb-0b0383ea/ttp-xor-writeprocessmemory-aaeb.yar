rule TTP_XOR_WriteProcessMemory_aaeb {
  strings:
    $key_aaeb = { fd 99 [2] cf bb [2] c9 8e [2] e7 8e [2] d8 92 }

  condition:
    any of them
}