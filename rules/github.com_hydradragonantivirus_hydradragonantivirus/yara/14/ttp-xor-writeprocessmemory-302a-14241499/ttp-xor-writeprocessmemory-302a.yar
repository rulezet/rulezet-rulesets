rule TTP_XOR_WriteProcessMemory_302a {
  strings:
    $key_302a = { 67 58 [2] 55 7a [2] 53 4f [2] 7d 4f [2] 42 53 }

  condition:
    any of them
}