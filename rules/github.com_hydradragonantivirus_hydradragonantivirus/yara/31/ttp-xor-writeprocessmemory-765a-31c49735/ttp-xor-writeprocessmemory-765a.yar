rule TTP_XOR_WriteProcessMemory_765a {
  strings:
    $key_765a = { 21 28 [2] 13 0a [2] 15 3f [2] 3b 3f [2] 04 23 }

  condition:
    any of them
}