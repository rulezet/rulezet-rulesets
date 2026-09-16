rule TTP_XOR_WriteProcessMemory_58e2 {
  strings:
    $key_58e2 = { 0f 90 [2] 3d b2 [2] 3b 87 [2] 15 87 [2] 2a 9b }

  condition:
    any of them
}