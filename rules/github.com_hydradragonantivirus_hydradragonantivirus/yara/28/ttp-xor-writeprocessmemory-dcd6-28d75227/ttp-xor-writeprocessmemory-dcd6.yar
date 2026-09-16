rule TTP_XOR_WriteProcessMemory_dcd6 {
  strings:
    $key_dcd6 = { 8b a4 [2] b9 86 [2] bf b3 [2] 91 b3 [2] ae af }

  condition:
    any of them
}