rule TTP_XOR_WriteProcessMemory_e32b {
  strings:
    $key_e32b = { b4 59 [2] 86 7b [2] 80 4e [2] ae 4e [2] 91 52 }

  condition:
    any of them
}