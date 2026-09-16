rule TTP_XOR_WriteProcessMemory_cb42 {
  strings:
    $key_cb42 = { 9c 30 [2] ae 12 [2] a8 27 [2] 86 27 [2] b9 3b }

  condition:
    any of them
}