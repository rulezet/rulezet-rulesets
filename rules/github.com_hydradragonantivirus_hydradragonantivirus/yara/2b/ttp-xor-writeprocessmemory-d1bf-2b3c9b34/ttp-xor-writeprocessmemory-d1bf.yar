rule TTP_XOR_WriteProcessMemory_d1bf {
  strings:
    $key_d1bf = { 86 cd [2] b4 ef [2] b2 da [2] 9c da [2] a3 c6 }

  condition:
    any of them
}