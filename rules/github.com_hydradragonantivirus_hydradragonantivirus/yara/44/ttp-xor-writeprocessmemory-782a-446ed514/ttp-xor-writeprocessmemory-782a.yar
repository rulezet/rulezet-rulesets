rule TTP_XOR_WriteProcessMemory_782a {
  strings:
    $key_782a = { 2f 58 [2] 1d 7a [2] 1b 4f [2] 35 4f [2] 0a 53 }

  condition:
    any of them
}