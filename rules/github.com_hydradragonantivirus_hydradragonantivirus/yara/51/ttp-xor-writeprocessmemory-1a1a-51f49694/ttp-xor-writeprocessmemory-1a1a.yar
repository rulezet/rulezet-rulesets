rule TTP_XOR_WriteProcessMemory_1a1a {
  strings:
    $key_1a1a = { 4d 68 [2] 7f 4a [2] 79 7f [2] 57 7f [2] 68 63 }

  condition:
    any of them
}