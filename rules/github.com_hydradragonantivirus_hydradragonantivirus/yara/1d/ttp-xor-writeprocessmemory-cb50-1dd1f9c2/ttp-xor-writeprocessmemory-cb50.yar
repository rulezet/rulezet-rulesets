rule TTP_XOR_WriteProcessMemory_cb50 {
  strings:
    $key_cb50 = { 9c 22 [2] ae 00 [2] a8 35 [2] 86 35 [2] b9 29 }

  condition:
    any of them
}