rule TTP_XOR_WriteProcessMemory_094a {
  strings:
    $key_094a = { 5e 38 [2] 6c 1a [2] 6a 2f [2] 44 2f [2] 7b 33 }

  condition:
    any of them
}