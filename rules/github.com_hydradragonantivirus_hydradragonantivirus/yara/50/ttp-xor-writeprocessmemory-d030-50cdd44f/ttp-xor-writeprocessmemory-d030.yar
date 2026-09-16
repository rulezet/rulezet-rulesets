rule TTP_XOR_WriteProcessMemory_d030 {
  strings:
    $key_d030 = { 87 42 [2] b5 60 [2] b3 55 [2] 9d 55 [2] a2 49 }

  condition:
    any of them
}