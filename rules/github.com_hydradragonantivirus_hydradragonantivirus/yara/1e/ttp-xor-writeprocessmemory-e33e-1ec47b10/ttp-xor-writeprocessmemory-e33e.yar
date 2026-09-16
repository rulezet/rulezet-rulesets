rule TTP_XOR_WriteProcessMemory_e33e {
  strings:
    $key_e33e = { b4 4c [2] 86 6e [2] 80 5b [2] ae 5b [2] 91 47 }

  condition:
    any of them
}