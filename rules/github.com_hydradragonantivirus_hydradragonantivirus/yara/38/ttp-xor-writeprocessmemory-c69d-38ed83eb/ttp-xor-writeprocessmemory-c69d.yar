rule TTP_XOR_WriteProcessMemory_c69d {
  strings:
    $key_c69d = { 91 ef [2] a3 cd [2] a5 f8 [2] 8b f8 [2] b4 e4 }

  condition:
    any of them
}