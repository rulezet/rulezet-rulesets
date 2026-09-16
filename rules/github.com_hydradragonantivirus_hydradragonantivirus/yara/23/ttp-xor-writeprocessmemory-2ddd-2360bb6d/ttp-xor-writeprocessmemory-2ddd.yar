rule TTP_XOR_WriteProcessMemory_2ddd {
  strings:
    $key_2ddd = { 7a af [2] 48 8d [2] 4e b8 [2] 60 b8 [2] 5f a4 }

  condition:
    any of them
}