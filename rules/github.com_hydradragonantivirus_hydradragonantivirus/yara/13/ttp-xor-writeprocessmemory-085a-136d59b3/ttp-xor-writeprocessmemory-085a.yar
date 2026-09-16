rule TTP_XOR_WriteProcessMemory_085a {
  strings:
    $key_085a = { 5f 28 [2] 6d 0a [2] 6b 3f [2] 45 3f [2] 7a 23 }

  condition:
    any of them
}