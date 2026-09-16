rule TTP_XOR_WriteProcessMemory_ca71 {
  strings:
    $key_ca71 = { 9d 03 [2] af 21 [2] a9 14 [2] 87 14 [2] b8 08 }

  condition:
    any of them
}