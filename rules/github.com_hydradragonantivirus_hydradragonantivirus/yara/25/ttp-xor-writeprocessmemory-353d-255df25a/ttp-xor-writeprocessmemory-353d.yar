rule TTP_XOR_WriteProcessMemory_353d {
  strings:
    $key_353d = { 62 4f [2] 50 6d [2] 56 58 [2] 78 58 [2] 47 44 }

  condition:
    any of them
}