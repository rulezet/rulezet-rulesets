rule TTP_XOR_WriteProcessMemory_436a {
  strings:
    $key_436a = { 14 18 [2] 26 3a [2] 20 0f [2] 0e 0f [2] 31 13 }

  condition:
    any of them
}