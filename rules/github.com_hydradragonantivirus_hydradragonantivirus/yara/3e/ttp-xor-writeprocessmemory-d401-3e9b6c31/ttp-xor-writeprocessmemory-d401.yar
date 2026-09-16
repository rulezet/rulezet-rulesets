rule TTP_XOR_WriteProcessMemory_d401 {
  strings:
    $key_d401 = { 83 73 [2] b1 51 [2] b7 64 [2] 99 64 [2] a6 78 }

  condition:
    any of them
}