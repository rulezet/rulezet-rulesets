rule TTP_XOR_WriteProcessMemory_f4da {
  strings:
    $key_f4da = { a3 a8 [2] 91 8a [2] 97 bf [2] b9 bf [2] 86 a3 }

  condition:
    any of them
}