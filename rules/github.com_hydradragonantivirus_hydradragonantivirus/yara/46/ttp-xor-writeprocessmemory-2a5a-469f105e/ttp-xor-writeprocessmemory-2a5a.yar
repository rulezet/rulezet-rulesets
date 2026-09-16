rule TTP_XOR_WriteProcessMemory_2a5a {
  strings:
    $key_2a5a = { 7d 28 [2] 4f 0a [2] 49 3f [2] 67 3f [2] 58 23 }

  condition:
    any of them
}