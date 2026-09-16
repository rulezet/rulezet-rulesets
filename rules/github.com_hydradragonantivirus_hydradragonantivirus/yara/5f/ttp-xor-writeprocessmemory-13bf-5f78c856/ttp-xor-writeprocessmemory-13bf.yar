rule TTP_XOR_WriteProcessMemory_13bf {
  strings:
    $key_13bf = { 44 cd [2] 76 ef [2] 70 da [2] 5e da [2] 61 c6 }

  condition:
    any of them
}