rule TTP_XOR_WriteProcessMemory_149d {
  strings:
    $key_149d = { 43 ef [2] 71 cd [2] 77 f8 [2] 59 f8 [2] 66 e4 }

  condition:
    any of them
}