rule TTP_XOR_WriteProcessMemory_d7bf {
  strings:
    $key_d7bf = { 80 cd [2] b2 ef [2] b4 da [2] 9a da [2] a5 c6 }

  condition:
    any of them
}