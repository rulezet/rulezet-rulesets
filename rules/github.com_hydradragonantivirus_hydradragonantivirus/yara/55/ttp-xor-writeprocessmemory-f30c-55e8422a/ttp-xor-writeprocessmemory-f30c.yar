rule TTP_XOR_WriteProcessMemory_f30c {
  strings:
    $key_f30c = { a4 7e [2] 96 5c [2] 90 69 [2] be 69 [2] 81 75 }

  condition:
    any of them
}