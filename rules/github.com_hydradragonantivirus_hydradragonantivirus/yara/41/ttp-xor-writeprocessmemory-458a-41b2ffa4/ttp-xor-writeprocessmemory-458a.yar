rule TTP_XOR_WriteProcessMemory_458a {
  strings:
    $key_458a = { 12 f8 [2] 20 da [2] 26 ef [2] 08 ef [2] 37 f3 }

  condition:
    any of them
}