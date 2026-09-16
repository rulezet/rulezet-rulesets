rule TTP_XOR_WriteProcessMemory_c0bf {
  strings:
    $key_c0bf = { 97 cd [2] a5 ef [2] a3 da [2] 8d da [2] b2 c6 }

  condition:
    any of them
}