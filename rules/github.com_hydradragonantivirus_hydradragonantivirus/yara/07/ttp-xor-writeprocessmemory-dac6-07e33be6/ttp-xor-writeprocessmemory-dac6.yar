rule TTP_XOR_WriteProcessMemory_dac6 {
  strings:
    $key_dac6 = { 8d b4 [2] bf 96 [2] b9 a3 [2] 97 a3 [2] a8 bf }

  condition:
    any of them
}