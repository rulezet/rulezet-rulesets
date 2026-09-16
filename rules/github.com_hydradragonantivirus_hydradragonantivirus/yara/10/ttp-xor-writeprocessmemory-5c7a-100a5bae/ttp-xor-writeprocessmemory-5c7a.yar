rule TTP_XOR_WriteProcessMemory_5c7a {
  strings:
    $key_5c7a = { 0b 08 [2] 39 2a [2] 3f 1f [2] 11 1f [2] 2e 03 }

  condition:
    any of them
}