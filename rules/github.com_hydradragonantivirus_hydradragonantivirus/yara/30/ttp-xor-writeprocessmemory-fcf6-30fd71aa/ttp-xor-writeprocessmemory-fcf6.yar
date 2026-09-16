rule TTP_XOR_WriteProcessMemory_fcf6 {
  strings:
    $key_fcf6 = { ab 84 [2] 99 a6 [2] 9f 93 [2] b1 93 [2] 8e 8f }

  condition:
    any of them
}