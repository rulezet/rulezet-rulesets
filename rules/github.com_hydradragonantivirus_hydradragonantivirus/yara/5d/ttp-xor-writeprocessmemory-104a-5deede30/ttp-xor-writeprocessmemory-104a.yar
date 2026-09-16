rule TTP_XOR_WriteProcessMemory_104a {
  strings:
    $key_104a = { 47 38 [2] 75 1a [2] 73 2f [2] 5d 2f [2] 62 33 }

  condition:
    any of them
}