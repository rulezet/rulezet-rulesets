rule TTP_XOR_WriteProcessMemory_27bf {
  strings:
    $key_27bf = { 70 cd [2] 42 ef [2] 44 da [2] 6a da [2] 55 c6 }

  condition:
    any of them
}