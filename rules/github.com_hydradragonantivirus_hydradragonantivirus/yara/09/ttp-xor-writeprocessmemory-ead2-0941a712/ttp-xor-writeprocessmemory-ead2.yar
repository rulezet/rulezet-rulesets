rule TTP_XOR_WriteProcessMemory_ead2 {
  strings:
    $key_ead2 = { bd a0 [2] 8f 82 [2] 89 b7 [2] a7 b7 [2] 98 ab }

  condition:
    any of them
}