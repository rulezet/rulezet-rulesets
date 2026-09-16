rule TTP_XOR_WriteProcessMemory_f44d {
  strings:
    $key_f44d = { a3 3f [2] 91 1d [2] 97 28 [2] b9 28 [2] 86 34 }

  condition:
    any of them
}