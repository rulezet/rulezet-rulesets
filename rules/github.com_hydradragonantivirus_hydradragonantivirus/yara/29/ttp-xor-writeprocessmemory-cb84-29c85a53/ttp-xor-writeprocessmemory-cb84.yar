rule TTP_XOR_WriteProcessMemory_cb84 {
  strings:
    $key_cb84 = { 9c f6 [2] ae d4 [2] a8 e1 [2] 86 e1 [2] b9 fd }

  condition:
    any of them
}