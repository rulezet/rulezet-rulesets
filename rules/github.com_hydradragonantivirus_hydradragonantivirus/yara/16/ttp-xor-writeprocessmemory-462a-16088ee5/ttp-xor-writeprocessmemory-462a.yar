rule TTP_XOR_WriteProcessMemory_462a {
  strings:
    $key_462a = { 11 58 [2] 23 7a [2] 25 4f [2] 0b 4f [2] 34 53 }

  condition:
    any of them
}