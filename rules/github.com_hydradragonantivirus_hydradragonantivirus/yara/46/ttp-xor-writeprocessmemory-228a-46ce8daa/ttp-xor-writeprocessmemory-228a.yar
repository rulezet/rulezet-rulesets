rule TTP_XOR_WriteProcessMemory_228a {
  strings:
    $key_228a = { 75 f8 [2] 47 da [2] 41 ef [2] 6f ef [2] 50 f3 }

  condition:
    any of them
}