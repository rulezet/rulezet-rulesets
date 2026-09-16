rule TTP_XOR_WriteProcessMemory_3f3a {
  strings:
    $key_3f3a = { 68 48 [2] 5a 6a [2] 5c 5f [2] 72 5f [2] 4d 43 }

  condition:
    any of them
}