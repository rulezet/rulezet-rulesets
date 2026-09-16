rule TTP_XOR_WriteProcessMemory_cb79 {
  strings:
    $key_cb79 = { 9c 0b [2] ae 29 [2] a8 1c [2] 86 1c [2] b9 00 }

  condition:
    any of them
}