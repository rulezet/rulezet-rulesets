rule TTP_XOR_WriteProcessMemory_657b {
  strings:
    $key_657b = { 32 09 [2] 00 2b [2] 06 1e [2] 28 1e [2] 17 02 }

  condition:
    any of them
}