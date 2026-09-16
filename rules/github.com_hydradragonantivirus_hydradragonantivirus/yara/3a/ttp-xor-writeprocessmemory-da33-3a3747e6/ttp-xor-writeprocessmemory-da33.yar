rule TTP_XOR_WriteProcessMemory_da33 {
  strings:
    $key_da33 = { 8d 41 [2] bf 63 [2] b9 56 [2] 97 56 [2] a8 4a }

  condition:
    any of them
}