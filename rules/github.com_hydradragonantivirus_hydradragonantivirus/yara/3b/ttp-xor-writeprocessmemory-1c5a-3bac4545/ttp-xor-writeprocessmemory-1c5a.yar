rule TTP_XOR_WriteProcessMemory_1c5a {
  strings:
    $key_1c5a = { 4b 28 [2] 79 0a [2] 7f 3f [2] 51 3f [2] 6e 23 }

  condition:
    any of them
}