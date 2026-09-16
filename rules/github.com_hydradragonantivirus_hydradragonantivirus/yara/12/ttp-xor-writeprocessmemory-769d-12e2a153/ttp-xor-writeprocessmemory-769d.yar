rule TTP_XOR_WriteProcessMemory_769d {
  strings:
    $key_769d = { 21 ef [2] 13 cd [2] 15 f8 [2] 3b f8 [2] 04 e4 }

  condition:
    any of them
}