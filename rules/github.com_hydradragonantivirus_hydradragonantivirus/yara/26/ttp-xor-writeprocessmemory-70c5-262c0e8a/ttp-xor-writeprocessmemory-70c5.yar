rule TTP_XOR_WriteProcessMemory_70c5 {
  strings:
    $key_70c5 = { 27 b7 [2] 15 95 [2] 13 a0 [2] 3d a0 [2] 02 bc }

  condition:
    any of them
}