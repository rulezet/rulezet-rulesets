rule TTP_XOR_WriteProcessMemory_cb74 {
  strings:
    $key_cb74 = { 9c 06 [2] ae 24 [2] a8 11 [2] 86 11 [2] b9 0d }

  condition:
    any of them
}