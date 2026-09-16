rule TTP_XOR_WriteProcessMemory_da01 {
  strings:
    $key_da01 = { 8d 73 [2] bf 51 [2] b9 64 [2] 97 64 [2] a8 78 }

  condition:
    any of them
}