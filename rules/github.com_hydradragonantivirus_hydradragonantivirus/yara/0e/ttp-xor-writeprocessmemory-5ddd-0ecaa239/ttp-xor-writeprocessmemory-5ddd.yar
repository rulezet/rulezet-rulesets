rule TTP_XOR_WriteProcessMemory_5ddd {
  strings:
    $key_5ddd = { 0a af [2] 38 8d [2] 3e b8 [2] 10 b8 [2] 2f a4 }

  condition:
    any of them
}