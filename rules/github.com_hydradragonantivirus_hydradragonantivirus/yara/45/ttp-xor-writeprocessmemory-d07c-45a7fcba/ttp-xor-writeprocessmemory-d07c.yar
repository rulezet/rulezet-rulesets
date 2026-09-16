rule TTP_XOR_WriteProcessMemory_d07c {
  strings:
    $key_d07c = { 87 0e [2] b5 2c [2] b3 19 [2] 9d 19 [2] a2 05 }

  condition:
    any of them
}