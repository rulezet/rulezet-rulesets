rule TTP_XOR_WriteProcessMemory_cb63 {
  strings:
    $key_cb63 = { 9c 11 [2] ae 33 [2] a8 06 [2] 86 06 [2] b9 1a }

  condition:
    any of them
}