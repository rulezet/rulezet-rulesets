rule TTP_XOR_WriteProcessMemory_366a {
  strings:
    $key_366a = { 61 18 [2] 53 3a [2] 55 0f [2] 7b 0f [2] 44 13 }

  condition:
    any of them
}