rule TTP_XOR_WriteProcessMemory_d071 {
  strings:
    $key_d071 = { 87 03 [2] b5 21 [2] b3 14 [2] 9d 14 [2] a2 08 }

  condition:
    any of them
}