rule TTP_XOR_WriteProcessMemory_156a {
  strings:
    $key_156a = { 42 18 [2] 70 3a [2] 76 0f [2] 58 0f [2] 67 13 }

  condition:
    any of them
}