rule TTP_XOR_WriteProcessMemory_f30d {
  strings:
    $key_f30d = { a4 7f [2] 96 5d [2] 90 68 [2] be 68 [2] 81 74 }

  condition:
    any of them
}