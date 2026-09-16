rule TTP_XOR_WriteProcessMemory_439d {
  strings:
    $key_439d = { 14 ef [2] 26 cd [2] 20 f8 [2] 0e f8 [2] 31 e4 }

  condition:
    any of them
}