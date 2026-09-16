rule TTP_XOR_WriteProcessMemory_f2d8 {
  strings:
    $key_f2d8 = { a5 aa [2] 97 88 [2] 91 bd [2] bf bd [2] 80 a1 }

  condition:
    any of them
}