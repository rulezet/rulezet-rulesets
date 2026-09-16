rule TTP_XOR_WriteProcessMemory_6e0a {
  strings:
    $key_6e0a = { 39 78 [2] 0b 5a [2] 0d 6f [2] 23 6f [2] 1c 73 }

  condition:
    any of them
}