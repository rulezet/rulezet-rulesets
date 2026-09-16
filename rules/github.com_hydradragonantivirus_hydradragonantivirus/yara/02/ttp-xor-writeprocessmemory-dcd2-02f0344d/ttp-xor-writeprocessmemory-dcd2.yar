rule TTP_XOR_WriteProcessMemory_dcd2 {
  strings:
    $key_dcd2 = { 8b a0 [2] b9 82 [2] bf b7 [2] 91 b7 [2] ae ab }

  condition:
    any of them
}