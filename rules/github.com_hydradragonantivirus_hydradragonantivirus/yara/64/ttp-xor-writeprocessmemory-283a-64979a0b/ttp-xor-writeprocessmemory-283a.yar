rule TTP_XOR_WriteProcessMemory_283a {
  strings:
    $key_283a = { 7f 48 [2] 4d 6a [2] 4b 5f [2] 65 5f [2] 5a 43 }

  condition:
    any of them
}