rule TTP_XOR_WriteProcessMemory_d2bf {
  strings:
    $key_d2bf = { 85 cd [2] b7 ef [2] b1 da [2] 9f da [2] a0 c6 }

  condition:
    any of them
}