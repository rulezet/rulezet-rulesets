rule TTP_XOR_WriteProcessMemory_6b4a {
  strings:
    $key_6b4a = { 3c 38 [2] 0e 1a [2] 08 2f [2] 26 2f [2] 19 33 }

  condition:
    any of them
}