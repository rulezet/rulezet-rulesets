rule TTP_XOR_WriteProcessMemory_379d {
  strings:
    $key_379d = { 60 ef [2] 52 cd [2] 54 f8 [2] 7a f8 [2] 45 e4 }

  condition:
    any of them
}