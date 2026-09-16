rule TTP_XOR_WriteProcessMemory_f33a {
  strings:
    $key_f33a = { a4 48 [2] 96 6a [2] 90 5f [2] be 5f [2] 81 43 }

  condition:
    any of them
}