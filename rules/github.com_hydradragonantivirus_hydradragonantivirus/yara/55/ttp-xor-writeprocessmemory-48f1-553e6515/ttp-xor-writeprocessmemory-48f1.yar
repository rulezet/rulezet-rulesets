rule TTP_XOR_WriteProcessMemory_48f1 {
  strings:
    $key_48f1 = { 1f 83 [2] 2d a1 [2] 2b 94 [2] 05 94 [2] 3a 88 }

  condition:
    any of them
}