rule TTP_XOR_WriteProcessMemory_455a {
  strings:
    $key_455a = { 12 28 [2] 20 0a [2] 26 3f [2] 08 3f [2] 37 23 }

  condition:
    any of them
}