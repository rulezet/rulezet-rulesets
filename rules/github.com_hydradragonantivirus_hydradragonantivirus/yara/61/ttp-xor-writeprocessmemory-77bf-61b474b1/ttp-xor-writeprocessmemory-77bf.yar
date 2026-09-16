rule TTP_XOR_WriteProcessMemory_77bf {
  strings:
    $key_77bf = { 20 cd [2] 12 ef [2] 14 da [2] 3a da [2] 05 c6 }

  condition:
    any of them
}