rule TTP_XOR_WriteProcessMemory_3b0a {
  strings:
    $key_3b0a = { 6c 78 [2] 5e 5a [2] 58 6f [2] 76 6f [2] 49 73 }

  condition:
    any of them
}