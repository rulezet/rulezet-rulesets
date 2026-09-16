rule TTP_XOR_WriteProcessMemory_7d5a {
  strings:
    $key_7d5a = { 2a 28 [2] 18 0a [2] 1e 3f [2] 30 3f [2] 0f 23 }

  condition:
    any of them
}