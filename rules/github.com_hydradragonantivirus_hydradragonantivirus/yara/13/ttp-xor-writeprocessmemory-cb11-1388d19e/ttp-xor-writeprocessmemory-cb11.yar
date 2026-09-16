rule TTP_XOR_WriteProcessMemory_cb11 {
  strings:
    $key_cb11 = { 9c 63 [2] ae 41 [2] a8 74 [2] 86 74 [2] b9 68 }

  condition:
    any of them
}