rule TTP_XOR_WriteProcessMemory_4c2a {
  strings:
    $key_4c2a = { 1b 58 [2] 29 7a [2] 2f 4f [2] 01 4f [2] 3e 53 }

  condition:
    any of them
}