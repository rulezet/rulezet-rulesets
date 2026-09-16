rule TTP_XOR_WriteProcessMemory_6f6a {
  strings:
    $key_6f6a = { 38 18 [2] 0a 3a [2] 0c 0f [2] 22 0f [2] 1d 13 }

  condition:
    any of them
}