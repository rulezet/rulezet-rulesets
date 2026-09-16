rule TTP_XOR_WriteProcessMemory_445a {
  strings:
    $key_445a = { 13 28 [2] 21 0a [2] 27 3f [2] 09 3f [2] 36 23 }

  condition:
    any of them
}