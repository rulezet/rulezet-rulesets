rule TTP_XOR_WriteProcessMemory_cb41 {
  strings:
    $key_cb41 = { 9c 33 [2] ae 11 [2] a8 24 [2] 86 24 [2] b9 38 }

  condition:
    any of them
}