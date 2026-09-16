rule TTP_XOR_WriteProcessMemory_ca8b {
  strings:
    $key_ca8b = { 9d f9 [2] af db [2] a9 ee [2] 87 ee [2] b8 f2 }

  condition:
    any of them
}