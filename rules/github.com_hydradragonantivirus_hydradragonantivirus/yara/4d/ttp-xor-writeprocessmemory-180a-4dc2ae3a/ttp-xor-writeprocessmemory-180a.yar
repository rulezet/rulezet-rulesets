rule TTP_XOR_WriteProcessMemory_180a {
  strings:
    $key_180a = { 4f 78 [2] 7d 5a [2] 7b 6f [2] 55 6f [2] 6a 73 }

  condition:
    any of them
}