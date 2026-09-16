rule TTP_XOR_WriteProcessMemory_cb13 {
  strings:
    $key_cb13 = { 9c 61 [2] ae 43 [2] a8 76 [2] 86 76 [2] b9 6a }

  condition:
    any of them
}