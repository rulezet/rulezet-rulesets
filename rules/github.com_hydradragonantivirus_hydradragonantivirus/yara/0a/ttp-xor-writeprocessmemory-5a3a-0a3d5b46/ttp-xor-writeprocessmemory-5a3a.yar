rule TTP_XOR_WriteProcessMemory_5a3a {
  strings:
    $key_5a3a = { 0d 48 [2] 3f 6a [2] 39 5f [2] 17 5f [2] 28 43 }

  condition:
    any of them
}