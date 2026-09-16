rule TTP_XOR_WriteProcessMemory_038a {
  strings:
    $key_038a = { 54 f8 [2] 66 da [2] 60 ef [2] 4e ef [2] 71 f3 }

  condition:
    any of them
}