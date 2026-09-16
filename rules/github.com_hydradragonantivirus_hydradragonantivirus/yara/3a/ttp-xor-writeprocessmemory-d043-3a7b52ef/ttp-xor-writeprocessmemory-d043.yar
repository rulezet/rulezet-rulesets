rule TTP_XOR_WriteProcessMemory_d043 {
  strings:
    $key_d043 = { 87 31 [2] b5 13 [2] b3 26 [2] 9d 26 [2] a2 3a }

  condition:
    any of them
}