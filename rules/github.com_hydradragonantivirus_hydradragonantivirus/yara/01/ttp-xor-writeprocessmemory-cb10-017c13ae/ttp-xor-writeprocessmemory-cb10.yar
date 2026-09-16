rule TTP_XOR_WriteProcessMemory_cb10 {
  strings:
    $key_cb10 = { 9c 62 [2] ae 40 [2] a8 75 [2] 86 75 [2] b9 69 }

  condition:
    any of them
}