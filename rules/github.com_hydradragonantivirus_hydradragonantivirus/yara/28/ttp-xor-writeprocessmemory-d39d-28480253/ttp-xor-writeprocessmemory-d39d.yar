rule TTP_XOR_WriteProcessMemory_d39d {
  strings:
    $key_d39d = { 84 ef [2] b6 cd [2] b0 f8 [2] 9e f8 [2] a1 e4 }

  condition:
    any of them
}