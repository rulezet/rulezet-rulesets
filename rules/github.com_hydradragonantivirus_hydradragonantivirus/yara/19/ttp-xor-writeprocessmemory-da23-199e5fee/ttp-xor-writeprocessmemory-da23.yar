rule TTP_XOR_WriteProcessMemory_da23 {
  strings:
    $key_da23 = { 8d 51 [2] bf 73 [2] b9 46 [2] 97 46 [2] a8 5a }

  condition:
    any of them
}