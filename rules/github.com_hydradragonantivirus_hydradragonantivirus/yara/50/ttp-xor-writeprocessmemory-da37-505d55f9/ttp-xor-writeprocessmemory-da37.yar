rule TTP_XOR_WriteProcessMemory_da37 {
  strings:
    $key_da37 = { 8d 45 [2] bf 67 [2] b9 52 [2] 97 52 [2] a8 4e }

  condition:
    any of them
}