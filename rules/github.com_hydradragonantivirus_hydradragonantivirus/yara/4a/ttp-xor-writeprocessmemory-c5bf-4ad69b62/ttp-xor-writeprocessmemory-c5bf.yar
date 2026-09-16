rule TTP_XOR_WriteProcessMemory_c5bf {
  strings:
    $key_c5bf = { 92 cd [2] a0 ef [2] a6 da [2] 88 da [2] b7 c6 }

  condition:
    any of them
}