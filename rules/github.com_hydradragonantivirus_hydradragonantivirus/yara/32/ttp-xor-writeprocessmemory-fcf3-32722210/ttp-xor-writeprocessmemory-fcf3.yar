rule TTP_XOR_WriteProcessMemory_fcf3 {
  strings:
    $key_fcf3 = { ab 81 [2] 99 a3 [2] 9f 96 [2] b1 96 [2] 8e 8a }

  condition:
    any of them
}