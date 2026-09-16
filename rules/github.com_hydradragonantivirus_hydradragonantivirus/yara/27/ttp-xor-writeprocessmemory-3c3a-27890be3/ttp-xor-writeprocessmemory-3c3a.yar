rule TTP_XOR_WriteProcessMemory_3c3a {
  strings:
    $key_3c3a = { 6b 48 [2] 59 6a [2] 5f 5f [2] 71 5f [2] 4e 43 }

  condition:
    any of them
}