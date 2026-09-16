rule TTP_XOR_WriteProcessMemory_f42d {
  strings:
    $key_f42d = { a3 5f [2] 91 7d [2] 97 48 [2] b9 48 [2] 86 54 }

  condition:
    any of them
}