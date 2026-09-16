rule TTP_XOR_WriteProcessMemory_17bf {
  strings:
    $key_17bf = { 40 cd [2] 72 ef [2] 74 da [2] 5a da [2] 65 c6 }

  condition:
    any of them
}