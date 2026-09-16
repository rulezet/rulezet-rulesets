rule TTP_XOR_WriteProcessMemory_cc9d {
  strings:
    $key_cc9d = { 9b ef [2] a9 cd [2] af f8 [2] 81 f8 [2] be e4 }

  condition:
    any of them
}