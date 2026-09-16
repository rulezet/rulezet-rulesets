rule TTP_XOR_WriteProcessMemory_465a {
  strings:
    $key_465a = { 11 28 [2] 23 0a [2] 25 3f [2] 0b 3f [2] 34 23 }

  condition:
    any of them
}