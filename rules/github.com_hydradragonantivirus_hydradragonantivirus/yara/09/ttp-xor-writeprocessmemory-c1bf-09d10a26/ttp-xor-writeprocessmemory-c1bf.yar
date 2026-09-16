rule TTP_XOR_WriteProcessMemory_c1bf {
  strings:
    $key_c1bf = { 96 cd [2] a4 ef [2] a2 da [2] 8c da [2] b3 c6 }

  condition:
    any of them
}