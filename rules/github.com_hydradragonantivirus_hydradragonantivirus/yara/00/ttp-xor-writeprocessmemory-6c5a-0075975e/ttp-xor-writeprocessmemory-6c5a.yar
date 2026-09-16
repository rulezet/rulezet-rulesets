rule TTP_XOR_WriteProcessMemory_6c5a {
  strings:
    $key_6c5a = { 3b 28 [2] 09 0a [2] 0f 3f [2] 21 3f [2] 1e 23 }

  condition:
    any of them
}