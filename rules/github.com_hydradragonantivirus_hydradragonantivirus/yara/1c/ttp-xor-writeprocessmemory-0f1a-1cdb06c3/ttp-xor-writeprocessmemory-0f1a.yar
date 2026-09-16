rule TTP_XOR_WriteProcessMemory_0f1a {
  strings:
    $key_0f1a = { 58 68 [2] 6a 4a [2] 6c 7f [2] 42 7f [2] 7d 63 }

  condition:
    any of them
}