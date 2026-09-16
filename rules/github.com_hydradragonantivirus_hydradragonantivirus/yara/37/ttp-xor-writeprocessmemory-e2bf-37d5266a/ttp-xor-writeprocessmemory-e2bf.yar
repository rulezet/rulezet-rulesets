rule TTP_XOR_WriteProcessMemory_e2bf {
  strings:
    $key_e2bf = { b5 cd [2] 87 ef [2] 81 da [2] af da [2] 90 c6 }

  condition:
    any of them
}