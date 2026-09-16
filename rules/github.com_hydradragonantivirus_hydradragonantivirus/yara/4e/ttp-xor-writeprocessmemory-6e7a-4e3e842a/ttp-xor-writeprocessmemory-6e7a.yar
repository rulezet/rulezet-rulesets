rule TTP_XOR_WriteProcessMemory_6e7a {
  strings:
    $key_6e7a = { 39 08 [2] 0b 2a [2] 0d 1f [2] 23 1f [2] 1c 03 }

  condition:
    any of them
}