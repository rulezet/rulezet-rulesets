rule TTP_XOR_WriteProcessMemory_559d {
  strings:
    $key_559d = { 02 ef [2] 30 cd [2] 36 f8 [2] 18 f8 [2] 27 e4 }

  condition:
    any of them
}