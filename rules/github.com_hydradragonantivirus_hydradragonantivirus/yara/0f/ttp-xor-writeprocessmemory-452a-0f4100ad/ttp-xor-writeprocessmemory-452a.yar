rule TTP_XOR_WriteProcessMemory_452a {
  strings:
    $key_452a = { 12 58 [2] 20 7a [2] 26 4f [2] 08 4f [2] 37 53 }

  condition:
    any of them
}