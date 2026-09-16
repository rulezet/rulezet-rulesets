rule TTP_XOR_WriteProcessMemory_0e5a {
  strings:
    $key_0e5a = { 59 28 [2] 6b 0a [2] 6d 3f [2] 43 3f [2] 7c 23 }

  condition:
    any of them
}