rule TTP_XOR_WriteProcessMemory_e561 {
  strings:
    $key_e561 = { b2 13 [2] 80 31 [2] 86 04 [2] a8 04 [2] 97 18 }

  condition:
    any of them
}