rule TTP_XOR_WriteProcessMemory_61bf {
  strings:
    $key_61bf = { 36 cd [2] 04 ef [2] 02 da [2] 2c da [2] 13 c6 }

  condition:
    any of them
}