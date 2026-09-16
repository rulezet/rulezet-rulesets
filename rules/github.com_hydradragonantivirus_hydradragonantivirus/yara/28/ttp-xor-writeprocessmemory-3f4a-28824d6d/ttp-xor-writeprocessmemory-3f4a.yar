rule TTP_XOR_WriteProcessMemory_3f4a {
  strings:
    $key_3f4a = { 68 38 [2] 5a 1a [2] 5c 2f [2] 72 2f [2] 4d 33 }

  condition:
    any of them
}