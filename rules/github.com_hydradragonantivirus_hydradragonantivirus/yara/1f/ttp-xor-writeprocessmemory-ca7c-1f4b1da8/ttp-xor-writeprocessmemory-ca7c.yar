rule TTP_XOR_WriteProcessMemory_ca7c {
  strings:
    $key_ca7c = { 9d 0e [2] af 2c [2] a9 19 [2] 87 19 [2] b8 05 }

  condition:
    any of them
}