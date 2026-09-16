rule TTP_XOR_WriteProcessMemory_409d {
  strings:
    $key_409d = { 17 ef [2] 25 cd [2] 23 f8 [2] 0d f8 [2] 32 e4 }

  condition:
    any of them
}