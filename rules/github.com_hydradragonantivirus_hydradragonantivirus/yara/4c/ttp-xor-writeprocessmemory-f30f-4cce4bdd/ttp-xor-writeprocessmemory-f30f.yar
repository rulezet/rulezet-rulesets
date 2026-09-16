rule TTP_XOR_WriteProcessMemory_f30f {
  strings:
    $key_f30f = { a4 7d [2] 96 5f [2] 90 6a [2] be 6a [2] 81 76 }

  condition:
    any of them
}