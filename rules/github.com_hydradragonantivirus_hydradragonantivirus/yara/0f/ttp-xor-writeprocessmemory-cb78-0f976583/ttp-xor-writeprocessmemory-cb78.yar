rule TTP_XOR_WriteProcessMemory_cb78 {
  strings:
    $key_cb78 = { 9c 0a [2] ae 28 [2] a8 1d [2] 86 1d [2] b9 01 }

  condition:
    any of them
}