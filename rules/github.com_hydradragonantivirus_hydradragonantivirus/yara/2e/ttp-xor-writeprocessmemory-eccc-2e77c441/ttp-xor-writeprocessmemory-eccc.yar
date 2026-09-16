rule TTP_XOR_WriteProcessMemory_eccc {
  strings:
    $key_eccc = { bb be [2] 89 9c [2] 8f a9 [2] a1 a9 [2] 9e b5 }

  condition:
    any of them
}