rule TTP_XOR_WriteProcessMemory_569d {
  strings:
    $key_569d = { 01 ef [2] 33 cd [2] 35 f8 [2] 1b f8 [2] 24 e4 }

  condition:
    any of them
}