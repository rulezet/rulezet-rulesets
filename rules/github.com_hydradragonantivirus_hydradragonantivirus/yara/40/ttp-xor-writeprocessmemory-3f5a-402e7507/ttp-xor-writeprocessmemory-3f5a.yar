rule TTP_XOR_WriteProcessMemory_3f5a {
  strings:
    $key_3f5a = { 68 28 [2] 5a 0a [2] 5c 3f [2] 72 3f [2] 4d 23 }

  condition:
    any of them
}