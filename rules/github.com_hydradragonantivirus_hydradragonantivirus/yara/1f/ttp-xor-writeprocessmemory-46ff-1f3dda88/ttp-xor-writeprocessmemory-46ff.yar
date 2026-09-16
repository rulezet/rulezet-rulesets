rule TTP_XOR_WriteProcessMemory_46ff {
  strings:
    $key_46ff = { 11 8d [2] 23 af [2] 25 9a [2] 0b 9a [2] 34 86 }

  condition:
    any of them
}