rule TTP_XOR_WriteProcessMemory_cb07 {
  strings:
    $key_cb07 = { 9c 75 [2] ae 57 [2] a8 62 [2] 86 62 [2] b9 7e }

  condition:
    any of them
}