rule TTP_XOR_WriteProcessMemory_ca01 {
  strings:
    $key_ca01 = { 9d 73 [2] af 51 [2] a9 64 [2] 87 64 [2] b8 78 }

  condition:
    any of them
}