rule TTP_XOR_WriteProcessMemory_c2bf {
  strings:
    $key_c2bf = { 95 cd [2] a7 ef [2] a1 da [2] 8f da [2] b0 c6 }

  condition:
    any of them
}