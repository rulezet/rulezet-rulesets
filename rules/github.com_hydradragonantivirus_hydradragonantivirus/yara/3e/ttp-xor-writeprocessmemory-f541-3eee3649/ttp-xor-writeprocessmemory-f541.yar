rule TTP_XOR_WriteProcessMemory_f541 {
  strings:
    $key_f541 = { a2 33 [2] 90 11 [2] 96 24 [2] b8 24 [2] 87 38 }

  condition:
    any of them
}