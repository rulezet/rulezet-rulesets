rule TTP_XOR_WriteProcessMemory_d020 {
  strings:
    $key_d020 = { 87 52 [2] b5 70 [2] b3 45 [2] 9d 45 [2] a2 59 }

  condition:
    any of them
}