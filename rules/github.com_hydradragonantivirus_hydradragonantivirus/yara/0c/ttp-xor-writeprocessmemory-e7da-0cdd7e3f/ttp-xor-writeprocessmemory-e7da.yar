rule TTP_XOR_WriteProcessMemory_e7da {
  strings:
    $key_e7da = { b0 a8 [2] 82 8a [2] 84 bf [2] aa bf [2] 95 a3 }

  condition:
    any of them
}