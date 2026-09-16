rule TTP_XOR_WriteProcessMemory_45ee {
  strings:
    $key_45ee = { 12 9c [2] 20 be [2] 26 8b [2] 08 8b [2] 37 97 }

  condition:
    any of them
}