rule TTP_XOR_WriteProcessMemory_a044 {
  strings:
    $key_a044 = { f7 36 [2] c5 14 [2] c3 21 [2] ed 21 [2] d2 3d }

  condition:
    any of them
}