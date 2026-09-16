rule TTP_XOR_WriteProcessMemory_7f0a {
  strings:
    $key_7f0a = { 28 78 [2] 1a 5a [2] 1c 6f [2] 32 6f [2] 0d 73 }

  condition:
    any of them
}