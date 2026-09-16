rule TTP_XOR_WriteProcessMemory_67bf {
  strings:
    $key_67bf = { 30 cd [2] 02 ef [2] 04 da [2] 2a da [2] 15 c6 }

  condition:
    any of them
}