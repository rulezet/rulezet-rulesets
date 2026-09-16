rule TTP_XOR_WriteProcessMemory_cb62 {
  strings:
    $key_cb62 = { 9c 10 [2] ae 32 [2] a8 07 [2] 86 07 [2] b9 1b }

  condition:
    any of them
}