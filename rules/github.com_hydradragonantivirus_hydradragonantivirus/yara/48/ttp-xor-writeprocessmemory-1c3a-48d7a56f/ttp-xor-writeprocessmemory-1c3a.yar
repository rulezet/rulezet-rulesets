rule TTP_XOR_WriteProcessMemory_1c3a {
  strings:
    $key_1c3a = { 4b 48 [2] 79 6a [2] 7f 5f [2] 51 5f [2] 6e 43 }

  condition:
    any of them
}