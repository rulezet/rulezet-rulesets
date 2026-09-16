rule TTP_XOR_WriteProcessMemory_8344 {
  strings:
    $key_8344 = { d4 36 [2] e6 14 [2] e0 21 [2] ce 21 [2] f1 3d }

  condition:
    any of them
}