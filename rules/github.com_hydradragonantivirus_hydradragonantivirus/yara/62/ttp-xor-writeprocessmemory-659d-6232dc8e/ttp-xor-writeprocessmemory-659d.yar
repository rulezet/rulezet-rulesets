rule TTP_XOR_WriteProcessMemory_659d {
  strings:
    $key_659d = { 32 ef [2] 00 cd [2] 06 f8 [2] 28 f8 [2] 17 e4 }

  condition:
    any of them
}