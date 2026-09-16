rule TTP_XOR_WriteProcessMemory_f2cd {
  strings:
    $key_f2cd = { a5 bf [2] 97 9d [2] 91 a8 [2] bf a8 [2] 80 b4 }

  condition:
    any of them
}