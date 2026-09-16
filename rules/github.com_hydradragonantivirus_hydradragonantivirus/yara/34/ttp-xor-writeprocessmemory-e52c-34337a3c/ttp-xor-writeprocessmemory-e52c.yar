rule TTP_XOR_WriteProcessMemory_e52c {
  strings:
    $key_e52c = { b2 5e [2] 80 7c [2] 86 49 [2] a8 49 [2] 97 55 }

  condition:
    any of them
}