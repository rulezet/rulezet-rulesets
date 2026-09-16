rule TTP_XOR_WriteProcessMemory_ca10 {
  strings:
    $key_ca10 = { 9d 62 [2] af 40 [2] a9 75 [2] 87 75 [2] b8 69 }

  condition:
    any of them
}