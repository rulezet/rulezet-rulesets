rule TTP_XOR_WriteProcessMemory_4c4a {
  strings:
    $key_4c4a = { 1b 38 [2] 29 1a [2] 2f 2f [2] 01 2f [2] 3e 33 }

  condition:
    any of them
}