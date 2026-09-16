rule TTP_XOR_WriteProcessMemory_794a {
  strings:
    $key_794a = { 2e 38 [2] 1c 1a [2] 1a 2f [2] 34 2f [2] 0b 33 }

  condition:
    any of them
}