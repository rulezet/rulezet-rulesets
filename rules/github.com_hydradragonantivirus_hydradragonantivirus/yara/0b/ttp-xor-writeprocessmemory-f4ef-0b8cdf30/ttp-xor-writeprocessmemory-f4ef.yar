rule TTP_XOR_WriteProcessMemory_f4ef {
  strings:
    $key_f4ef = { a3 9d [2] 91 bf [2] 97 8a [2] b9 8a [2] 86 96 }

  condition:
    any of them
}