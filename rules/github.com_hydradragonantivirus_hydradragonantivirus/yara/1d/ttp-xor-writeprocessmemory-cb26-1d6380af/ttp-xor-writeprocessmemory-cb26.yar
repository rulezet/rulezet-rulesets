rule TTP_XOR_WriteProcessMemory_cb26 {
  strings:
    $key_cb26 = { 9c 54 [2] ae 76 [2] a8 43 [2] 86 43 [2] b9 5f }

  condition:
    any of them
}