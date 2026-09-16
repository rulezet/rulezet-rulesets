rule TTP_XOR_WriteProcessMemory_0f2a {
  strings:
    $key_0f2a = { 58 58 [2] 6a 7a [2] 6c 4f [2] 42 4f [2] 7d 53 }

  condition:
    any of them
}