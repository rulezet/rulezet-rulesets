rule TTP_XOR_WriteProcessMemory_284a {
  strings:
    $key_284a = { 7f 38 [2] 4d 1a [2] 4b 2f [2] 65 2f [2] 5a 33 }

  condition:
    any of them
}