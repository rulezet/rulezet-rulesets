rule TTP_XOR_WriteProcessMemory_d08a {
  strings:
    $key_d08a = { 87 f8 [2] b5 da [2] b3 ef [2] 9d ef [2] a2 f3 }

  condition:
    any of them
}