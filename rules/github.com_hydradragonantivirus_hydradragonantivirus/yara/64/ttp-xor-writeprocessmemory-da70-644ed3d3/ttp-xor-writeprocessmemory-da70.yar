rule TTP_XOR_WriteProcessMemory_da70 {
  strings:
    $key_da70 = { 8d 02 [2] bf 20 [2] b9 15 [2] 97 15 [2] a8 09 }

  condition:
    any of them
}