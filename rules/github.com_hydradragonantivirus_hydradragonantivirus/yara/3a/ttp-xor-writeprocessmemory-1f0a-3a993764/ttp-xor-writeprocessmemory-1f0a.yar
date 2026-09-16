rule TTP_XOR_WriteProcessMemory_1f0a {
  strings:
    $key_1f0a = { 48 78 [2] 7a 5a [2] 7c 6f [2] 52 6f [2] 6d 73 }

  condition:
    any of them
}