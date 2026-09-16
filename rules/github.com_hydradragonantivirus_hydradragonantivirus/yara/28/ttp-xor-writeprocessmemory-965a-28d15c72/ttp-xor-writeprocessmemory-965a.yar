rule TTP_XOR_WriteProcessMemory_965a {
  strings:
    $key_965a = { c1 28 [2] f3 0a [2] f5 3f [2] db 3f [2] e4 23 }

  condition:
    any of them
}