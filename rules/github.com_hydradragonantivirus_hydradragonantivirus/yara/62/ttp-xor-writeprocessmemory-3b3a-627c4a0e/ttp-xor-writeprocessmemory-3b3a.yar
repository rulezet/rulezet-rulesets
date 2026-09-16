rule TTP_XOR_WriteProcessMemory_3b3a {
  strings:
    $key_3b3a = { 6c 48 [2] 5e 6a [2] 58 5f [2] 76 5f [2] 49 43 }

  condition:
    any of them
}