rule TTP_XOR_WriteProcessMemory_466a {
  strings:
    $key_466a = { 11 18 [2] 23 3a [2] 25 0f [2] 0b 0f [2] 34 13 }

  condition:
    any of them
}