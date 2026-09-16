rule TTP_XOR_WriteProcessMemory_dcd3 {
  strings:
    $key_dcd3 = { 8b a1 [2] b9 83 [2] bf b6 [2] 91 b6 [2] ae aa }

  condition:
    any of them
}