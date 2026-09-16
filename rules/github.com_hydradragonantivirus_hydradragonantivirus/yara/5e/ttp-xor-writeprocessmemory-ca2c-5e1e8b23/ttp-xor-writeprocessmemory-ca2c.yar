rule TTP_XOR_WriteProcessMemory_ca2c {
  strings:
    $key_ca2c = { 9d 5e [2] af 7c [2] a9 49 [2] 87 49 [2] b8 55 }

  condition:
    any of them
}