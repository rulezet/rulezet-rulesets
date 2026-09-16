rule TTP_XOR_WriteProcessMemory_c0ee {
  strings:
    $key_c0ee = { 97 9c [2] a5 be [2] a3 8b [2] 8d 8b [2] b2 97 }

  condition:
    any of them
}