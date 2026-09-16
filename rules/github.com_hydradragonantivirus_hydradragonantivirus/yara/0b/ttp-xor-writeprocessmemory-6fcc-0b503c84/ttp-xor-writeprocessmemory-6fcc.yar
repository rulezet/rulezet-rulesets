rule TTP_XOR_WriteProcessMemory_6fcc {
  strings:
    $key_6fcc = { 38 be [2] 0a 9c [2] 0c a9 [2] 22 a9 [2] 1d b5 }

  condition:
    any of them
}