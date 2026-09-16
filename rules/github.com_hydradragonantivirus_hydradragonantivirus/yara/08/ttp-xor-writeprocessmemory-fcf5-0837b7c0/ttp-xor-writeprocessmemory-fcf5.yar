rule TTP_XOR_WriteProcessMemory_fcf5 {
  strings:
    $key_fcf5 = { ab 87 [2] 99 a5 [2] 9f 90 [2] b1 90 [2] 8e 8c }

  condition:
    any of them
}