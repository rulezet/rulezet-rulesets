rule TTP_XOR_WriteProcessMemory_1f3a {
  strings:
    $key_1f3a = { 48 48 [2] 7a 6a [2] 7c 5f [2] 52 5f [2] 6d 43 }

  condition:
    any of them
}