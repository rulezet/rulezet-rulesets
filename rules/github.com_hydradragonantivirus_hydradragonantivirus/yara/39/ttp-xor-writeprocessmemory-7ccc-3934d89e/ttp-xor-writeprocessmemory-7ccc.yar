rule TTP_XOR_WriteProcessMemory_7ccc {
  strings:
    $key_7ccc = { 2b be [2] 19 9c [2] 1f a9 [2] 31 a9 [2] 0e b5 }

  condition:
    any of them
}