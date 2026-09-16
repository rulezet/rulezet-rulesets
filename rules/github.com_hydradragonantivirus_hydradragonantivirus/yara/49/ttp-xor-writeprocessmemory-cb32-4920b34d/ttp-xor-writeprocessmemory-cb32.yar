rule TTP_XOR_WriteProcessMemory_cb32 {
  strings:
    $key_cb32 = { 9c 40 [2] ae 62 [2] a8 57 [2] 86 57 [2] b9 4b }

  condition:
    any of them
}