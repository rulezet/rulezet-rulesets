rule TTP_XOR_WriteProcessMemory_44ff {
  strings:
    $key_44ff = { 13 8d [2] 21 af [2] 27 9a [2] 09 9a [2] 36 86 }

  condition:
    any of them
}