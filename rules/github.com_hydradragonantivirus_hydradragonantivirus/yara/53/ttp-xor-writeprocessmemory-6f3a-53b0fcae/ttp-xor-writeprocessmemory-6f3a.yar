rule TTP_XOR_WriteProcessMemory_6f3a {
  strings:
    $key_6f3a = { 38 48 [2] 0a 6a [2] 0c 5f [2] 22 5f [2] 1d 43 }

  condition:
    any of them
}