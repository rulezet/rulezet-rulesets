rule TTP_XOR_WriteProcessMemory_e51b {
  strings:
    $key_e51b = { b2 69 [2] 80 4b [2] 86 7e [2] a8 7e [2] 97 62 }

  condition:
    any of them
}