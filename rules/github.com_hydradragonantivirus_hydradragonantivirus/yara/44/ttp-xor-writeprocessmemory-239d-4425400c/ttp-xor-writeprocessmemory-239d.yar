rule TTP_XOR_WriteProcessMemory_239d {
  strings:
    $key_239d = { 74 ef [2] 46 cd [2] 40 f8 [2] 6e f8 [2] 51 e4 }

  condition:
    any of them
}