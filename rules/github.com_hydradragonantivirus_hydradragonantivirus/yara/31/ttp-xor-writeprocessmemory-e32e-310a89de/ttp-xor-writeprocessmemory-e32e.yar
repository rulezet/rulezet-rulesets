rule TTP_XOR_WriteProcessMemory_e32e {
  strings:
    $key_e32e = { b4 5c [2] 86 7e [2] 80 4b [2] ae 4b [2] 91 57 }

  condition:
    any of them
}