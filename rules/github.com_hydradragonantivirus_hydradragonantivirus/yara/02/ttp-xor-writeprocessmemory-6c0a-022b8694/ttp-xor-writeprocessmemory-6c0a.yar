rule TTP_XOR_WriteProcessMemory_6c0a {
  strings:
    $key_6c0a = { 3b 78 [2] 09 5a [2] 0f 6f [2] 21 6f [2] 1e 73 }

  condition:
    any of them
}