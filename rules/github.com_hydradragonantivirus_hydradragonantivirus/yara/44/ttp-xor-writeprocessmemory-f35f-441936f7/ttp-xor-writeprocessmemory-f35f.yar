rule TTP_XOR_WriteProcessMemory_f35f {
  strings:
    $key_f35f = { a4 2d [2] 96 0f [2] 90 3a [2] be 3a [2] 81 26 }

  condition:
    any of them
}