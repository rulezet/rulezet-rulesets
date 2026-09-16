rule TTP_XOR_WriteProcessMemory_6e6a {
  strings:
    $key_6e6a = { 39 18 [2] 0b 3a [2] 0d 0f [2] 23 0f [2] 1c 13 }

  condition:
    any of them
}