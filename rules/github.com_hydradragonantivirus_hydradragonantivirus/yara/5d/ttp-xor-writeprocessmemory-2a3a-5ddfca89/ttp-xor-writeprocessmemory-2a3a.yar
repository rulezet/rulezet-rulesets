rule TTP_XOR_WriteProcessMemory_2a3a {
  strings:
    $key_2a3a = { 7d 48 [2] 4f 6a [2] 49 5f [2] 67 5f [2] 58 43 }

  condition:
    any of them
}