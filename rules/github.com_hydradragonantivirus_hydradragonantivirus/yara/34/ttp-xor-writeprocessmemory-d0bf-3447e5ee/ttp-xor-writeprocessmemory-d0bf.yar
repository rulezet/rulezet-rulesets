rule TTP_XOR_WriteProcessMemory_d0bf {
  strings:
    $key_d0bf = { 87 cd [2] b5 ef [2] b3 da [2] 9d da [2] a2 c6 }

  condition:
    any of them
}