rule TTP_XOR_WriteProcessMemory_518a {
  strings:
    $key_518a = { 06 f8 [2] 34 da [2] 32 ef [2] 1c ef [2] 23 f3 }

  condition:
    any of them
}