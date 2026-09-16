rule TTP_XOR_WriteProcessMemory_da14 {
  strings:
    $key_da14 = { 8d 66 [2] bf 44 [2] b9 71 [2] 97 71 [2] a8 6d }

  condition:
    any of them
}