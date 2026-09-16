rule TTP_XOR_WriteProcessMemory_75ff {
  strings:
    $key_75ff = { 22 8d [2] 10 af [2] 16 9a [2] 38 9a [2] 07 86 }

  condition:
    any of them
}