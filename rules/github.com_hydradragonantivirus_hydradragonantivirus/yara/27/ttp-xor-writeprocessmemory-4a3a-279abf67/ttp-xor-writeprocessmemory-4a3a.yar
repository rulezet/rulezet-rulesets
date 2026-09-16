rule TTP_XOR_WriteProcessMemory_4a3a {
  strings:
    $key_4a3a = { 1d 48 [2] 2f 6a [2] 29 5f [2] 07 5f [2] 38 43 }

  condition:
    any of them
}