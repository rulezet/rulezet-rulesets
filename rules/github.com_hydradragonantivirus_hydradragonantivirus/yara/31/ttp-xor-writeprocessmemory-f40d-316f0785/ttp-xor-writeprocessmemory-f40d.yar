rule TTP_XOR_WriteProcessMemory_f40d {
  strings:
    $key_f40d = { a3 7f [2] 91 5d [2] 97 68 [2] b9 68 [2] 86 74 }

  condition:
    any of them
}