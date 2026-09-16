rule TTP_XOR_WriteProcessMemory_401a {
  strings:
    $key_401a = { 17 68 [2] 25 4a [2] 23 7f [2] 0d 7f [2] 32 63 }

  condition:
    any of them
}