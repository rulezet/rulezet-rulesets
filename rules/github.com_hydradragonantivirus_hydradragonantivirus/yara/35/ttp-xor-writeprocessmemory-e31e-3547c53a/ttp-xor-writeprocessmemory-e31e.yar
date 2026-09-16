rule TTP_XOR_WriteProcessMemory_e31e {
  strings:
    $key_e31e = { b4 6c [2] 86 4e [2] 80 7b [2] ae 7b [2] 91 67 }

  condition:
    any of them
}