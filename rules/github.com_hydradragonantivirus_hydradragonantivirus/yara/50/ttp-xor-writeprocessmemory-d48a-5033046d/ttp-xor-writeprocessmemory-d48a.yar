rule TTP_XOR_WriteProcessMemory_d48a {
  strings:
    $key_d48a = { 83 f8 [2] b1 da [2] b7 ef [2] 99 ef [2] a6 f3 }

  condition:
    any of them
}