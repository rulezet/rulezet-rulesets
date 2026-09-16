rule TTP_XOR_WriteProcessMemory_685a {
  strings:
    $key_685a = { 3f 28 [2] 0d 0a [2] 0b 3f [2] 25 3f [2] 1a 23 }

  condition:
    any of them
}