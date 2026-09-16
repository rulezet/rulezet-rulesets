rule TTP_XOR_WriteProcessMemory_3fcc {
  strings:
    $key_3fcc = { 68 be [2] 5a 9c [2] 5c a9 [2] 72 a9 [2] 4d b5 }

  condition:
    any of them
}