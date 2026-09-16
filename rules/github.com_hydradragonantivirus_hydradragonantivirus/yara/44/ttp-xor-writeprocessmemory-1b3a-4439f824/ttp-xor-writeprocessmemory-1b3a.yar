rule TTP_XOR_WriteProcessMemory_1b3a {
  strings:
    $key_1b3a = { 4c 48 [2] 7e 6a [2] 78 5f [2] 56 5f [2] 69 43 }

  condition:
    any of them
}