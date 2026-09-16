rule TTP_XOR_WriteProcessMemory_cb65 {
  strings:
    $key_cb65 = { 9c 17 [2] ae 35 [2] a8 00 [2] 86 00 [2] b9 1c }

  condition:
    any of them
}