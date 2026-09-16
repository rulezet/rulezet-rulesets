rule TTP_XOR_WriteProcessMemory_d003 {
  strings:
    $key_d003 = { 87 71 [2] b5 53 [2] b3 66 [2] 9d 66 [2] a2 7a }

  condition:
    any of them
}