rule TTP_XOR_WriteProcessMemory_f42c {
  strings:
    $key_f42c = { a3 5e [2] 91 7c [2] 97 49 [2] b9 49 [2] 86 55 }

  condition:
    any of them
}