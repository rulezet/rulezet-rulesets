rule TTP_XOR_WriteProcessMemory_1b5a {
  strings:
    $key_1b5a = { 4c 28 [2] 7e 0a [2] 78 3f [2] 56 3f [2] 69 23 }

  condition:
    any of them
}