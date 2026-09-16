rule TTP_XOR_WriteProcessMemory_686a {
  strings:
    $key_686a = { 3f 18 [2] 0d 3a [2] 0b 0f [2] 25 0f [2] 1a 13 }

  condition:
    any of them
}