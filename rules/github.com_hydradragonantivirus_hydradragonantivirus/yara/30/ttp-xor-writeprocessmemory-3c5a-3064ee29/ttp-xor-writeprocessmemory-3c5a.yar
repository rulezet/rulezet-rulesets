rule TTP_XOR_WriteProcessMemory_3c5a {
  strings:
    $key_3c5a = { 6b 28 [2] 59 0a [2] 5f 3f [2] 71 3f [2] 4e 23 }

  condition:
    any of them
}