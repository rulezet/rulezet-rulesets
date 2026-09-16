rule TTP_XOR_WriteProcessMemory_f3cd {
  strings:
    $key_f3cd = { a4 bf [2] 96 9d [2] 90 a8 [2] be a8 [2] 81 b4 }

  condition:
    any of them
}