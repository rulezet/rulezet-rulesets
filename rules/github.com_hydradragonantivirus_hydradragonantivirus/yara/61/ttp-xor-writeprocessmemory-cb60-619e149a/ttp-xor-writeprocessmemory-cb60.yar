rule TTP_XOR_WriteProcessMemory_cb60 {
  strings:
    $key_cb60 = { 9c 12 [2] ae 30 [2] a8 05 [2] 86 05 [2] b9 19 }

  condition:
    any of them
}