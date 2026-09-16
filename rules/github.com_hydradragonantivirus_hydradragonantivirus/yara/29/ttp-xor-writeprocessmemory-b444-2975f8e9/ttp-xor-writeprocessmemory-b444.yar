rule TTP_XOR_WriteProcessMemory_b444 {
  strings:
    $key_b444 = { e3 36 [2] d1 14 [2] d7 21 [2] f9 21 [2] c6 3d }

  condition:
    any of them
}