rule TTP_XOR_WriteProcessMemory_cb53 {
  strings:
    $key_cb53 = { 9c 21 [2] ae 03 [2] a8 36 [2] 86 36 [2] b9 2a }

  condition:
    any of them
}