rule TTP_XOR_WriteProcessMemory_6c3a {
  strings:
    $key_6c3a = { 3b 48 [2] 09 6a [2] 0f 5f [2] 21 5f [2] 1e 43 }

  condition:
    any of them
}