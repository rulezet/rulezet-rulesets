rule TTP_XOR_WriteProcessMemory_0ae5 {
  strings:
    $key_0ae5 = { 5d 97 [2] 6f b5 [2] 69 80 [2] 47 80 [2] 78 9c }

  condition:
    any of them
}