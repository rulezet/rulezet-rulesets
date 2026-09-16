rule TTP_XOR_WriteProcessMemory_cb96 {
  strings:
    $key_cb96 = { 9c e4 [2] ae c6 [2] a8 f3 [2] 86 f3 [2] b9 ef }

  condition:
    any of them
}