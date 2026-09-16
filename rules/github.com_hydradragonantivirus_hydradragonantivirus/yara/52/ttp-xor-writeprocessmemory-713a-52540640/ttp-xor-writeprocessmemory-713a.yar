rule TTP_XOR_WriteProcessMemory_713a {
  strings:
    $key_713a = { 26 48 [2] 14 6a [2] 12 5f [2] 3c 5f [2] 03 43 }

  condition:
    any of them
}