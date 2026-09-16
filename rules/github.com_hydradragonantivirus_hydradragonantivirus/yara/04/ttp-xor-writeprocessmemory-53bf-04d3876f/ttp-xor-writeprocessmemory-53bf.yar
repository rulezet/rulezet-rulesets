rule TTP_XOR_WriteProcessMemory_53bf {
  strings:
    $key_53bf = { 04 cd [2] 36 ef [2] 30 da [2] 1e da [2] 21 c6 }

  condition:
    any of them
}