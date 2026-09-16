rule TTP_XOR_WriteProcessMemory_26bf {
  strings:
    $key_26bf = { 71 cd [2] 43 ef [2] 45 da [2] 6b da [2] 54 c6 }

  condition:
    any of them
}