rule TTP_XOR_WriteProcessMemory_ca55 {
  strings:
    $key_ca55 = { 9d 27 [2] af 05 [2] a9 30 [2] 87 30 [2] b8 2c }

  condition:
    any of them
}