rule TTP_XOR_WriteProcessMemory_e2da {
  strings:
    $key_e2da = { b5 a8 [2] 87 8a [2] 81 bf [2] af bf [2] 90 a3 }

  condition:
    any of them
}