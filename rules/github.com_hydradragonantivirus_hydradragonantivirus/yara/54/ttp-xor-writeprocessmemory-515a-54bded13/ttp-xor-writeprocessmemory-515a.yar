rule TTP_XOR_WriteProcessMemory_515a {
  strings:
    $key_515a = { 06 28 [2] 34 0a [2] 32 3f [2] 1c 3f [2] 23 23 }

  condition:
    any of them
}