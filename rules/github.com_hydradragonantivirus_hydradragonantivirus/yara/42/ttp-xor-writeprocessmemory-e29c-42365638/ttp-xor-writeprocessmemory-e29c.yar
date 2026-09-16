rule TTP_XOR_WriteProcessMemory_e29c {
  strings:
    $key_e29c = { b5 ee [2] 87 cc [2] 81 f9 [2] af f9 [2] 90 e5 }

  condition:
    any of them
}