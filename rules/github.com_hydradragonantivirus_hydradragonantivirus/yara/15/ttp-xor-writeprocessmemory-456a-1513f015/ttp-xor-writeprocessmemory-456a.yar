rule TTP_XOR_WriteProcessMemory_456a {
  strings:
    $key_456a = { 12 18 [2] 20 3a [2] 26 0f [2] 08 0f [2] 37 13 }

  condition:
    any of them
}