rule TTP_XOR_WriteProcessMemory_cda1 {
  strings:
    $key_cda1 = { 9a d3 [2] a8 f1 [2] ae c4 [2] 80 c4 [2] bf d8 }

  condition:
    any of them
}