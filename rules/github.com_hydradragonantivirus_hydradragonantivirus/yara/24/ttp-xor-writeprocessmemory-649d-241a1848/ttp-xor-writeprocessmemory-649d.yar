rule TTP_XOR_WriteProcessMemory_649d {
  strings:
    $key_649d = { 33 ef [2] 01 cd [2] 07 f8 [2] 29 f8 [2] 16 e4 }

  condition:
    any of them
}