rule TTP_XOR_WriteProcessMemory_f45c {
  strings:
    $key_f45c = { a3 2e [2] 91 0c [2] 97 39 [2] b9 39 [2] 86 25 }

  condition:
    any of them
}