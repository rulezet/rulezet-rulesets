rule TTP_XOR_WriteProcessMemory_5cff {
  strings:
    $key_5cff = { 0b 8d [2] 39 af [2] 3f 9a [2] 11 9a [2] 2e 86 }

  condition:
    any of them
}