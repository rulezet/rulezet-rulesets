rule TTP_XOR_WriteProcessMemory_7b0a {
  strings:
    $key_7b0a = { 2c 78 [2] 1e 5a [2] 18 6f [2] 36 6f [2] 09 73 }

  condition:
    any of them
}