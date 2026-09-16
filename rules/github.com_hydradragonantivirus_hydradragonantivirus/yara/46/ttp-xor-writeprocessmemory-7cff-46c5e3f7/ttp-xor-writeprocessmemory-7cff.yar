rule TTP_XOR_WriteProcessMemory_7cff {
  strings:
    $key_7cff = { 2b 8d [2] 19 af [2] 1f 9a [2] 31 9a [2] 0e 86 }

  condition:
    any of them
}