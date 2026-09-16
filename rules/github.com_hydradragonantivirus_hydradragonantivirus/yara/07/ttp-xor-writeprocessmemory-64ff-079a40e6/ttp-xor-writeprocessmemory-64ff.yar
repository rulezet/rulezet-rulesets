rule TTP_XOR_WriteProcessMemory_64ff {
  strings:
    $key_64ff = { 33 8d [2] 01 af [2] 07 9a [2] 29 9a [2] 16 86 }

  condition:
    any of them
}