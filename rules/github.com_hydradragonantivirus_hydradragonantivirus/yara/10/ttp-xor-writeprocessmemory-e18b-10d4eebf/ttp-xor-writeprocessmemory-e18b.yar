rule TTP_XOR_WriteProcessMemory_e18b {
  strings:
    $key_e18b = { b6 f9 [2] 84 db [2] 82 ee [2] ac ee [2] 93 f2 }

  condition:
    any of them
}