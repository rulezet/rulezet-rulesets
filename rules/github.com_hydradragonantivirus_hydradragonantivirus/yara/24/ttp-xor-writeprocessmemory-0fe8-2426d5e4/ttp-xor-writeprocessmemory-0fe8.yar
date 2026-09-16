rule TTP_XOR_WriteProcessMemory_0fe8 {
  strings:
    $key_0fe8 = { 58 9a [2] 6a b8 [2] 6c 8d [2] 42 8d [2] 7d 91 }

  condition:
    any of them
}