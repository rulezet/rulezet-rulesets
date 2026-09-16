rule TTP_XOR_WriteProcessMemory_8317 {
  strings:
    $key_8317 = { d4 65 [2] e6 47 [2] e0 72 [2] ce 72 [2] f1 6e }

  condition:
    any of them
}