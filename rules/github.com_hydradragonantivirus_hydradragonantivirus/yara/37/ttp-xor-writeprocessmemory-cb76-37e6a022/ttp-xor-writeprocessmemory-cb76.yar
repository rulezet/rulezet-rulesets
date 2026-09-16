rule TTP_XOR_WriteProcessMemory_cb76 {
  strings:
    $key_cb76 = { 9c 04 [2] ae 26 [2] a8 13 [2] 86 13 [2] b9 0f }

  condition:
    any of them
}