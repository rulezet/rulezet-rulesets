rule TTP_XOR_WriteProcessMemory_cb00 {
  strings:
    $key_cb00 = { 9c 72 [2] ae 50 [2] a8 65 [2] 86 65 [2] b9 79 }

  condition:
    any of them
}