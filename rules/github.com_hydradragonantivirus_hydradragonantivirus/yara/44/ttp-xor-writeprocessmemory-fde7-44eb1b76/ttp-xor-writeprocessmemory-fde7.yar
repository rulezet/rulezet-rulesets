rule TTP_XOR_WriteProcessMemory_fde7 {
  strings:
    $key_fde7 = { aa 95 [2] 98 b7 [2] 9e 82 [2] b0 82 [2] 8f 9e }

  condition:
    any of them
}