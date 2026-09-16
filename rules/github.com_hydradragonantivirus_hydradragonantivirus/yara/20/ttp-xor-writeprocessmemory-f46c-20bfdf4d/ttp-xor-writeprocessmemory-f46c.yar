rule TTP_XOR_WriteProcessMemory_f46c {
  strings:
    $key_f46c = { a3 1e [2] 91 3c [2] 97 09 [2] b9 09 [2] 86 15 }

  condition:
    any of them
}