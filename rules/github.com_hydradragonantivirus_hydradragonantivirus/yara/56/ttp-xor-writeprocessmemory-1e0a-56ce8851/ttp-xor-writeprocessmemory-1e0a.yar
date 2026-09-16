rule TTP_XOR_WriteProcessMemory_1e0a {
  strings:
    $key_1e0a = { 49 78 [2] 7b 5a [2] 7d 6f [2] 53 6f [2] 6c 73 }

  condition:
    any of them
}