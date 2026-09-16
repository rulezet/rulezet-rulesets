rule TTP_XOR_WriteProcessMemory_152a {
  strings:
    $key_152a = { 42 58 [2] 70 7a [2] 76 4f [2] 58 4f [2] 67 53 }

  condition:
    any of them
}