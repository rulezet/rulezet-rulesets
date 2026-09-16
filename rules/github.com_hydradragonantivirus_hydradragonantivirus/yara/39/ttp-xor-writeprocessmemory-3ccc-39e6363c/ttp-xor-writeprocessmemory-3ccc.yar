rule TTP_XOR_WriteProcessMemory_3ccc {
  strings:
    $key_3ccc = { 6b be [2] 59 9c [2] 5f a9 [2] 71 a9 [2] 4e b5 }

  condition:
    any of them
}