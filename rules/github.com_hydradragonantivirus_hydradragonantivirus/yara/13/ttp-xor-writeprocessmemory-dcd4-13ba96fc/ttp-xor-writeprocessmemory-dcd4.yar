rule TTP_XOR_WriteProcessMemory_dcd4 {
  strings:
    $key_dcd4 = { 8b a6 [2] b9 84 [2] bf b1 [2] 91 b1 [2] ae ad }

  condition:
    any of them
}