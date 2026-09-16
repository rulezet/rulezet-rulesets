rule TTP_XOR_WriteProcessMemory_da11 {
  strings:
    $key_da11 = { 8d 63 [2] bf 41 [2] b9 74 [2] 97 74 [2] a8 68 }

  condition:
    any of them
}