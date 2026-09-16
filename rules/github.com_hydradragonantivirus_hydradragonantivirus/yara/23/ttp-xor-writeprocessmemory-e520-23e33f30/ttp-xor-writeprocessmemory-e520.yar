rule TTP_XOR_WriteProcessMemory_e520 {
  strings:
    $key_e520 = { b2 52 [2] 80 70 [2] 86 45 [2] a8 45 [2] 97 59 }

  condition:
    any of them
}