rule TTP_XOR_WriteProcessMemory_48a3 {
  strings:
    $key_48a3 = { 1f d1 [2] 2d f3 [2] 2b c6 [2] 05 c6 [2] 3a da }

  condition:
    any of them
}