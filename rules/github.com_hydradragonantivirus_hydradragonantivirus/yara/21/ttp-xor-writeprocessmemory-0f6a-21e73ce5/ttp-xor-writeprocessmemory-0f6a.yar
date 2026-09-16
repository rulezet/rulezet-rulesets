rule TTP_XOR_WriteProcessMemory_0f6a {
  strings:
    $key_0f6a = { 58 18 [2] 6a 3a [2] 6c 0f [2] 42 0f [2] 7d 13 }

  condition:
    any of them
}