rule TTP_XOR_WriteProcessMemory_07bf {
  strings:
    $key_07bf = { 50 cd [2] 62 ef [2] 64 da [2] 4a da [2] 75 c6 }

  condition:
    any of them
}