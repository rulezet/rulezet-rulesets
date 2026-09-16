rule TTP_XOR_WriteProcessMemory_d09d {
  strings:
    $key_d09d = { 87 ef [2] b5 cd [2] b3 f8 [2] 9d f8 [2] a2 e4 }

  condition:
    any of them
}