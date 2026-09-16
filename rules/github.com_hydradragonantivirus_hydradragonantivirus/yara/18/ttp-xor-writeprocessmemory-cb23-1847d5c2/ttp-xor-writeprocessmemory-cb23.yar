rule TTP_XOR_WriteProcessMemory_cb23 {
  strings:
    $key_cb23 = { 9c 51 [2] ae 73 [2] a8 46 [2] 86 46 [2] b9 5a }

  condition:
    any of them
}