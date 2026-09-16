rule TTP_XOR_WriteProcessMemory_683a {
  strings:
    $key_683a = { 3f 48 [2] 0d 6a [2] 0b 5f [2] 25 5f [2] 1a 43 }

  condition:
    any of them
}