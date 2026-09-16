rule TTP_XOR_WriteProcessMemory_ca20 {
  strings:
    $key_ca20 = { 9d 52 [2] af 70 [2] a9 45 [2] 87 45 [2] b8 59 }

  condition:
    any of them
}