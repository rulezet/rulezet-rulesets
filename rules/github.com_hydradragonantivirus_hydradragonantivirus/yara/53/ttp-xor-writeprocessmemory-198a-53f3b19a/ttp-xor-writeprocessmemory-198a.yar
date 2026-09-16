rule TTP_XOR_WriteProcessMemory_198a {
  strings:
    $key_198a = { 4e f8 [2] 7c da [2] 7a ef [2] 54 ef [2] 6b f3 }

  condition:
    any of them
}