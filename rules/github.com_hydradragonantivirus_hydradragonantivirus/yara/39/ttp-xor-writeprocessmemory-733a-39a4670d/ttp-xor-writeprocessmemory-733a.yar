rule TTP_XOR_WriteProcessMemory_733a {
  strings:
    $key_733a = { 24 48 [2] 16 6a [2] 10 5f [2] 3e 5f [2] 01 43 }

  condition:
    any of them
}