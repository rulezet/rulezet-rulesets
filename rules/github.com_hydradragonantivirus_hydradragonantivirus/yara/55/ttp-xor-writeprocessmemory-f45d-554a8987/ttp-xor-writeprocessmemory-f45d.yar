rule TTP_XOR_WriteProcessMemory_f45d {
  strings:
    $key_f45d = { a3 2f [2] 91 0d [2] 97 38 [2] b9 38 [2] 86 24 }

  condition:
    any of them
}