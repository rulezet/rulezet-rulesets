rule TTP_XOR_WriteProcessMemory_7ddd {
  strings:
    $key_7ddd = { 2a af [2] 18 8d [2] 1e b8 [2] 30 b8 [2] 0f a4 }

  condition:
    any of them
}