rule TTP_XOR_WriteProcessMemory_65ff {
  strings:
    $key_65ff = { 32 8d [2] 00 af [2] 06 9a [2] 28 9a [2] 17 86 }

  condition:
    any of them
}