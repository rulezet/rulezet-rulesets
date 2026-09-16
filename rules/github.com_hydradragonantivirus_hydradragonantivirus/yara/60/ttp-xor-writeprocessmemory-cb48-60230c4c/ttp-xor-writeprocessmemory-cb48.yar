rule TTP_XOR_WriteProcessMemory_cb48 {
  strings:
    $key_cb48 = { 9c 3a [2] ae 18 [2] a8 2d [2] 86 2d [2] b9 31 }

  condition:
    any of them
}