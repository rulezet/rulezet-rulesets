rule TTP_XOR_WriteProcessMemory_4ddd {
  strings:
    $key_4ddd = { 1a af [2] 28 8d [2] 2e b8 [2] 00 b8 [2] 3f a4 }

  condition:
    any of them
}