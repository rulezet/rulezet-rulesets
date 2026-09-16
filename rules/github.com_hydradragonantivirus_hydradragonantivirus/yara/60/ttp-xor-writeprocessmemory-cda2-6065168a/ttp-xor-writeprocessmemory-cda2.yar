rule TTP_XOR_WriteProcessMemory_cda2 {
  strings:
    $key_cda2 = { 9a d0 [2] a8 f2 [2] ae c7 [2] 80 c7 [2] bf db }

  condition:
    any of them
}