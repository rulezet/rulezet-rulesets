rule TTP_XOR_WriteProcessMemory_f2ef {
  strings:
    $key_f2ef = { a5 9d [2] 97 bf [2] 91 8a [2] bf 8a [2] 80 96 }

  condition:
    any of them
}