rule TTP_XOR_WriteProcessMemory_3b6a {
  strings:
    $key_3b6a = { 6c 18 [2] 5e 3a [2] 58 0f [2] 76 0f [2] 49 13 }

  condition:
    any of them
}