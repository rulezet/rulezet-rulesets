rule TTP_XOR_WriteProcessMemory_f36f {
  strings:
    $key_f36f = { a4 1d [2] 96 3f [2] 90 0a [2] be 0a [2] 81 16 }

  condition:
    any of them
}