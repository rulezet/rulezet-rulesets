rule TTP_XOR_WriteProcessMemory_e465 {
  strings:
    $key_e465 = { b3 17 [2] 81 35 [2] 87 00 [2] a9 00 [2] 96 1c }

  condition:
    any of them
}