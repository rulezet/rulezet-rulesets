rule TTP_XOR_WriteProcessMemory_da03 {
  strings:
    $key_da03 = { 8d 71 [2] bf 53 [2] b9 66 [2] 97 66 [2] a8 7a }

  condition:
    any of them
}