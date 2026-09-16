rule TTP_XOR_WriteProcessMemory_47bf {
  strings:
    $key_47bf = { 10 cd [2] 22 ef [2] 24 da [2] 0a da [2] 35 c6 }

  condition:
    any of them
}