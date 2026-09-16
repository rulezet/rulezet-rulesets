rule TTP_XOR_WriteProcessMemory_792a {
  strings:
    $key_792a = { 2e 58 [2] 1c 7a [2] 1a 4f [2] 34 4f [2] 0b 53 }

  condition:
    any of them
}