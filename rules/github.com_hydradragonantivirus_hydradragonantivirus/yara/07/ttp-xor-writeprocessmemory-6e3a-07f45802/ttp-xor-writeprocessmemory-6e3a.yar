rule TTP_XOR_WriteProcessMemory_6e3a {
  strings:
    $key_6e3a = { 39 48 [2] 0b 6a [2] 0d 5f [2] 23 5f [2] 1c 43 }

  condition:
    any of them
}