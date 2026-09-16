rule TTP_XOR_WriteProcessMemory_42e3 {
  strings:
    $key_42e3 = { 15 91 [2] 27 b3 [2] 21 86 [2] 0f 86 [2] 30 9a }

  condition:
    any of them
}