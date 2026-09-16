rule TTP_XOR_WriteProcessMemory_0ddd {
  strings:
    $key_0ddd = { 5a af [2] 68 8d [2] 6e b8 [2] 40 b8 [2] 7f a4 }

  condition:
    any of them
}