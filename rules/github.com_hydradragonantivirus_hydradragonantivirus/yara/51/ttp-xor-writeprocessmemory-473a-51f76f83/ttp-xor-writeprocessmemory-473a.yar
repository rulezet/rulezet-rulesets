rule TTP_XOR_WriteProcessMemory_473a {
  strings:
    $key_473a = { 10 48 [2] 22 6a [2] 24 5f [2] 0a 5f [2] 35 43 }

  condition:
    any of them
}