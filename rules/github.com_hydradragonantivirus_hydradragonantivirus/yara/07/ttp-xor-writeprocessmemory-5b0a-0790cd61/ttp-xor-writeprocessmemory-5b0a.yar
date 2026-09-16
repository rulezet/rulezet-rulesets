rule TTP_XOR_WriteProcessMemory_5b0a {
  strings:
    $key_5b0a = { 0c 78 [2] 3e 5a [2] 38 6f [2] 16 6f [2] 29 73 }

  condition:
    any of them
}