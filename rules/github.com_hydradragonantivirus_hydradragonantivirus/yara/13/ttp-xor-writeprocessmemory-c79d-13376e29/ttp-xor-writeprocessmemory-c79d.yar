rule TTP_XOR_WriteProcessMemory_c79d {
  strings:
    $key_c79d = { 90 ef [2] a2 cd [2] a4 f8 [2] 8a f8 [2] b5 e4 }

  condition:
    any of them
}