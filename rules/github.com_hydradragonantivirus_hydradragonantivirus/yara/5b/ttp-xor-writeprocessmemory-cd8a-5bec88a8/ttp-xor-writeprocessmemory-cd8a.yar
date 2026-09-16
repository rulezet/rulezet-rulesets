rule TTP_XOR_WriteProcessMemory_cd8a {
  strings:
    $key_cd8a = { 9a f8 [2] a8 da [2] ae ef [2] 80 ef [2] bf f3 }

  condition:
    any of them
}