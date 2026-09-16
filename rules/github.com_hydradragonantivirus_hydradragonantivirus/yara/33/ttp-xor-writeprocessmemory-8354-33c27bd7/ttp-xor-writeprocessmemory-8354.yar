rule TTP_XOR_WriteProcessMemory_8354 {
  strings:
    $key_8354 = { d4 26 [2] e6 04 [2] e0 31 [2] ce 31 [2] f1 2d }

  condition:
    any of them
}