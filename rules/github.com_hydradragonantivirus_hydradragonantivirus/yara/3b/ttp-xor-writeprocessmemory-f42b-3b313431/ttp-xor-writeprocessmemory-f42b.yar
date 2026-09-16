rule TTP_XOR_WriteProcessMemory_f42b {
  strings:
    $key_f42b = { a3 59 [2] 91 7b [2] 97 4e [2] b9 4e [2] 86 52 }

  condition:
    any of them
}