rule TTP_XOR_WriteProcessMemory_cb2c {
  strings:
    $key_cb2c = { 9c 5e [2] ae 7c [2] a8 49 [2] 86 49 [2] b9 55 }

  condition:
    any of them
}