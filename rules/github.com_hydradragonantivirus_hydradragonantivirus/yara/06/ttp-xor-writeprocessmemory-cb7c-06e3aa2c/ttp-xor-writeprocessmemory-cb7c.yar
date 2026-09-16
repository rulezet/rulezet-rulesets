rule TTP_XOR_WriteProcessMemory_cb7c {
  strings:
    $key_cb7c = { 9c 0e [2] ae 2c [2] a8 19 [2] 86 19 [2] b9 05 }

  condition:
    any of them
}