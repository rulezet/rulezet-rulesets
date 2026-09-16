rule TTP_XOR_WriteProcessMemory_48a5 {
  strings:
    $key_48a5 = { 1f d7 [2] 2d f5 [2] 2b c0 [2] 05 c0 [2] 3a dc }

  condition:
    any of them
}