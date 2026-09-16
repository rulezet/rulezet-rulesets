rule TTP_XOR_WriteProcessMemory_42e8 {
  strings:
    $key_42e8 = { 15 9a [2] 27 b8 [2] 21 8d [2] 0f 8d [2] 30 91 }

  condition:
    any of them
}