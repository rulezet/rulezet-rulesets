rule TTP_XOR_WriteProcessMemory_c86a {
  strings:
    $key_c86a = { 9f 18 [2] ad 3a [2] ab 0f [2] 85 0f [2] ba 13 }

  condition:
    any of them
}