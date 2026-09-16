rule TTP_XOR_WriteProcessMemory_694a {
  strings:
    $key_694a = { 3e 38 [2] 0c 1a [2] 0a 2f [2] 24 2f [2] 1b 33 }

  condition:
    any of them
}