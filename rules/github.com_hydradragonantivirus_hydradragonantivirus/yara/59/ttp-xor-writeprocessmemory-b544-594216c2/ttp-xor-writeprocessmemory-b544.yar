rule TTP_XOR_WriteProcessMemory_b544 {
  strings:
    $key_b544 = { e2 36 [2] d0 14 [2] d6 21 [2] f8 21 [2] c7 3d }

  condition:
    any of them
}