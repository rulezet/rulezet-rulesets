rule TTP_XOR_WriteProcessMemory_265a {
  strings:
    $key_265a = { 71 28 [2] 43 0a [2] 45 3f [2] 6b 3f [2] 54 23 }

  condition:
    any of them
}