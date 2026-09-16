rule TTP_XOR_WriteProcessMemory_daf4 {
  strings:
    $key_daf4 = { 8d 86 [2] bf a4 [2] b9 91 [2] 97 91 [2] a8 8d }

  condition:
    any of them
}