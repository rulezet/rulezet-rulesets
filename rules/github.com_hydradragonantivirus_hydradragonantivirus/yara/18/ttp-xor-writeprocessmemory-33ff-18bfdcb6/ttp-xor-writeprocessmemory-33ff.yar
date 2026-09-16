rule TTP_XOR_WriteProcessMemory_33ff {
  strings:
    $key_33ff = { 64 8d [2] 56 af [2] 50 9a [2] 7e 9a [2] 41 86 }

  condition:
    any of them
}