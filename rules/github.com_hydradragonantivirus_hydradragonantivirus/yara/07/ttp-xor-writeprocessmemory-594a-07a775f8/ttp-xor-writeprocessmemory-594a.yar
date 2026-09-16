rule TTP_XOR_WriteProcessMemory_594a {
  strings:
    $key_594a = { 0e 38 [2] 3c 1a [2] 3a 2f [2] 14 2f [2] 2b 33 }

  condition:
    any of them
}