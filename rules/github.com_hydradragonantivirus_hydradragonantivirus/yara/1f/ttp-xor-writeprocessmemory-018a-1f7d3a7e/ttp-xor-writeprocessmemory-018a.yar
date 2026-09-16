rule TTP_XOR_WriteProcessMemory_018a {
  strings:
    $key_018a = { 56 f8 [2] 64 da [2] 62 ef [2] 4c ef [2] 73 f3 }

  condition:
    any of them
}