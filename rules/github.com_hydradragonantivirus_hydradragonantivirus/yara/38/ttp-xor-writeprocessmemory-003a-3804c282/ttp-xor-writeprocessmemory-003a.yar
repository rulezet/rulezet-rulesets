rule TTP_XOR_WriteProcessMemory_003a {
  strings:
    $key_003a = { 57 48 [2] 65 6a [2] 63 5f [2] 4d 5f [2] 72 43 }

  condition:
    any of them
}