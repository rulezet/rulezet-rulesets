rule TTP_XOR_WriteProcessMemory_f2cf {
  strings:
    $key_f2cf = { a5 bd [2] 97 9f [2] 91 aa [2] bf aa [2] 80 b6 }

  condition:
    any of them
}