rule TTP_XOR_WriteProcessMemory_da8a {
  strings:
    $key_da8a = { 8d f8 [2] bf da [2] b9 ef [2] 97 ef [2] a8 f3 }

  condition:
    any of them
}