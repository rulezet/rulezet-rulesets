rule TTP_XOR_WriteProcessMemory_40ff {
  strings:
    $key_40ff = { 17 8d [2] 25 af [2] 23 9a [2] 0d 9a [2] 32 86 }

  condition:
    any of them
}