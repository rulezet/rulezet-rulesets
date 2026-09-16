rule TTP_XOR_WriteProcessMemory_cb56 {
  strings:
    $key_cb56 = { 9c 24 [2] ae 06 [2] a8 33 [2] 86 33 [2] b9 2f }

  condition:
    any of them
}