rule TTP_XOR_WriteProcessMemory_618a {
  strings:
    $key_618a = { 36 f8 [2] 04 da [2] 02 ef [2] 2c ef [2] 13 f3 }

  condition:
    any of them
}