rule TTP_XOR_WriteProcessMemory_f455 {
  strings:
    $key_f455 = { a3 27 [2] 91 05 [2] 97 30 [2] b9 30 [2] 86 2c }

  condition:
    any of them
}