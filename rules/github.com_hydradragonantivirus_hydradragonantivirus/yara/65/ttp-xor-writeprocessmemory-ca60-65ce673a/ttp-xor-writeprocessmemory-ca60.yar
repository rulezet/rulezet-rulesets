rule TTP_XOR_WriteProcessMemory_ca60 {
  strings:
    $key_ca60 = { 9d 12 [2] af 30 [2] a9 05 [2] 87 05 [2] b8 19 }

  condition:
    any of them
}