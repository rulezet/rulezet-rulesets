rule TTP_XOR_WriteProcessMemory_3a3a {
  strings:
    $key_3a3a = { 6d 48 [2] 5f 6a [2] 59 5f [2] 77 5f [2] 48 43 }

  condition:
    any of them
}