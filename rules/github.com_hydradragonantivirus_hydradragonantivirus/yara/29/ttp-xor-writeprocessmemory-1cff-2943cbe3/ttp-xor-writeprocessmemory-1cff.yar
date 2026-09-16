rule TTP_XOR_WriteProcessMemory_1cff {
  strings:
    $key_1cff = { 4b 8d [2] 79 af [2] 7f 9a [2] 51 9a [2] 6e 86 }

  condition:
    any of them
}