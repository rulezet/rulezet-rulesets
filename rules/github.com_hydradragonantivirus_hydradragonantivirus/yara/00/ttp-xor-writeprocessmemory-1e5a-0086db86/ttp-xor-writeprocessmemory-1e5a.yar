rule TTP_XOR_WriteProcessMemory_1e5a {
  strings:
    $key_1e5a = { 49 28 [2] 7b 0a [2] 7d 3f [2] 53 3f [2] 6c 23 }

  condition:
    any of them
}