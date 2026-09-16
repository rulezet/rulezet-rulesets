rule TTP_XOR_WriteProcessMemory_6e2a {
  strings:
    $key_6e2a = { 39 58 [2] 0b 7a [2] 0d 4f [2] 23 4f [2] 1c 53 }

  condition:
    any of them
}