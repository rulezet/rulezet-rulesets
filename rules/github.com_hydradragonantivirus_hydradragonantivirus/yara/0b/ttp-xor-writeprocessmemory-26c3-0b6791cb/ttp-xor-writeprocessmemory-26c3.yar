rule TTP_XOR_WriteProcessMemory_26c3 {
  strings:
    $key_26c3 = { 71 b1 [2] 43 93 [2] 45 a6 [2] 6b a6 [2] 54 ba }

  condition:
    any of them
}