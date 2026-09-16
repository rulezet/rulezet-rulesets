rule TTP_XOR_WriteProcessMemory_e33b {
  strings:
    $key_e33b = { b4 49 [2] 86 6b [2] 80 5e [2] ae 5e [2] 91 42 }

  condition:
    any of them
}