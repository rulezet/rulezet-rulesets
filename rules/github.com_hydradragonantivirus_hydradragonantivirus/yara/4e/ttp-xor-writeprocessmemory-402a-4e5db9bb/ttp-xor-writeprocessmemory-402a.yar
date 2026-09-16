rule TTP_XOR_WriteProcessMemory_402a {
  strings:
    $key_402a = { 17 58 [2] 25 7a [2] 23 4f [2] 0d 4f [2] 32 53 }

  condition:
    any of them
}