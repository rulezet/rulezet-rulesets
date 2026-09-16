rule TTP_XOR_WriteProcessMemory_f40c {
  strings:
    $key_f40c = { a3 7e [2] 91 5c [2] 97 69 [2] b9 69 [2] 86 75 }

  condition:
    any of them
}