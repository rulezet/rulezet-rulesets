rule TTP_XOR_WriteProcessMemory_cb03 {
  strings:
    $key_cb03 = { 9c 71 [2] ae 53 [2] a8 66 [2] 86 66 [2] b9 7a }

  condition:
    any of them
}