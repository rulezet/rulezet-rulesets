rule TTP_XOR_WriteProcessMemory_3d12 {
  strings:
    $key_3d12 = { 6a 60 [2] 58 42 [2] 5e 77 [2] 70 77 [2] 4f 6b }

  condition:
    any of them
}