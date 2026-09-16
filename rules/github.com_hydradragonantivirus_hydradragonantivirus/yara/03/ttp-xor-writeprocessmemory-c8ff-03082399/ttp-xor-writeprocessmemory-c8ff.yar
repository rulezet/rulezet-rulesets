rule TTP_XOR_WriteProcessMemory_c8ff {
  strings:
    $key_c8ff = { 9f 8d [2] ad af [2] ab 9a [2] 85 9a [2] ba 86 }

  condition:
    any of them
}