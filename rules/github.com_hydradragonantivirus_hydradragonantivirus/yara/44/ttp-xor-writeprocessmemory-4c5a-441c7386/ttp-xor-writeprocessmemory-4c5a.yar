rule TTP_XOR_WriteProcessMemory_4c5a {
  strings:
    $key_4c5a = { 1b 28 [2] 29 0a [2] 2f 3f [2] 01 3f [2] 3e 23 }

  condition:
    any of them
}