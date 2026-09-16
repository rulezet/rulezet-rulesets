rule TTP_XOR_WriteProcessMemory_724a {
  strings:
    $key_724a = { 25 38 [2] 17 1a [2] 11 2f [2] 3f 2f [2] 00 33 }

  condition:
    any of them
}