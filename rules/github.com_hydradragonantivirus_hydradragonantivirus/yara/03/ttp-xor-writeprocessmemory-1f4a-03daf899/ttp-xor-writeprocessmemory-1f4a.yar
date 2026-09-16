rule TTP_XOR_WriteProcessMemory_1f4a {
  strings:
    $key_1f4a = { 48 38 [2] 7a 1a [2] 7c 2f [2] 52 2f [2] 6d 33 }

  condition:
    any of them
}