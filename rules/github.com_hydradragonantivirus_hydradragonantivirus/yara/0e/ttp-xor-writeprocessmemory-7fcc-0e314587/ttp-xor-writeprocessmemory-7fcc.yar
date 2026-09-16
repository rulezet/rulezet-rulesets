rule TTP_XOR_WriteProcessMemory_7fcc {
  strings:
    $key_7fcc = { 28 be [2] 1a 9c [2] 1c a9 [2] 32 a9 [2] 0d b5 }

  condition:
    any of them
}