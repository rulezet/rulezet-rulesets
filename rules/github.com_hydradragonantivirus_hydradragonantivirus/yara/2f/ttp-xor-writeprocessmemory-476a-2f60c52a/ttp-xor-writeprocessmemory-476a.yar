rule TTP_XOR_WriteProcessMemory_476a {
  strings:
    $key_476a = { 10 18 [2] 22 3a [2] 24 0f [2] 0a 0f [2] 35 13 }

  condition:
    any of them
}