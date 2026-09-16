rule TTP_XOR_WriteProcessMemory_c86e {
  strings:
    $key_c86e = { 9f 1c [2] ad 3e [2] ab 0b [2] 85 0b [2] ba 17 }

  condition:
    any of them
}