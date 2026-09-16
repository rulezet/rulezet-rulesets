rule TTP_XOR_WriteProcessMemory_229d {
  strings:
    $key_229d = { 75 ef [2] 47 cd [2] 41 f8 [2] 6f f8 [2] 50 e4 }

  condition:
    any of them
}