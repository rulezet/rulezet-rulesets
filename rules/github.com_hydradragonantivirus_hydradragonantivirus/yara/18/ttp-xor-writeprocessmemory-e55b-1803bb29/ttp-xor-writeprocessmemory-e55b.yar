rule TTP_XOR_WriteProcessMemory_e55b {
  strings:
    $key_e55b = { b2 29 [2] 80 0b [2] 86 3e [2] a8 3e [2] 97 22 }

  condition:
    any of them
}