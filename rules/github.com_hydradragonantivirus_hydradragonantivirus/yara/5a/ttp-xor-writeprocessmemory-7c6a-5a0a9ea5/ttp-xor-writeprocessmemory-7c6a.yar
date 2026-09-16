rule TTP_XOR_WriteProcessMemory_7c6a {
  strings:
    $key_7c6a = { 2b 18 [2] 19 3a [2] 1f 0f [2] 31 0f [2] 0e 13 }

  condition:
    any of them
}