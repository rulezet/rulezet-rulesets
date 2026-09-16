rule TTP_XOR_WriteProcessMemory_7f3a {
  strings:
    $key_7f3a = { 28 48 [2] 1a 6a [2] 1c 5f [2] 32 5f [2] 0d 43 }

  condition:
    any of them
}