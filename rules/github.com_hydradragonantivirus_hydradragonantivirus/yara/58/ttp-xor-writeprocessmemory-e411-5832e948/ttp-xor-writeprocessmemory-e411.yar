rule TTP_XOR_WriteProcessMemory_e411 {
  strings:
    $key_e411 = { b3 63 [2] 81 41 [2] 87 74 [2] a9 74 [2] 96 68 }

  condition:
    any of them
}