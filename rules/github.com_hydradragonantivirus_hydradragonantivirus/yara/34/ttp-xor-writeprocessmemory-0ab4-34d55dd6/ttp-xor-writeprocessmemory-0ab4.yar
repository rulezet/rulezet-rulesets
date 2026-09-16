rule TTP_XOR_WriteProcessMemory_0ab4 {
  strings:
    $key_0ab4 = { 5d c6 [2] 6f e4 [2] 69 d1 [2] 47 d1 [2] 78 cd }

  condition:
    any of them
}