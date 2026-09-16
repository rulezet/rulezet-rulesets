rule TTP_XOR_WriteProcessMemory_dea5 {
  strings:
    $key_dea5 = { 89 d7 [2] bb f5 [2] bd c0 [2] 93 c0 [2] ac dc }

  condition:
    any of them
}