rule TTP_XOR_WriteProcessMemory_e28b {
  strings:
    $key_e28b = { b5 f9 [2] 87 db [2] 81 ee [2] af ee [2] 90 f2 }

  condition:
    any of them
}