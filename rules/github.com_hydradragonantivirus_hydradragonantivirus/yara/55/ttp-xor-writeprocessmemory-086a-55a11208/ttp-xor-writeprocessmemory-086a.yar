rule TTP_XOR_WriteProcessMemory_086a {
  strings:
    $key_086a = { 5f 18 [2] 6d 3a [2] 6b 0f [2] 45 0f [2] 7a 13 }

  condition:
    any of them
}