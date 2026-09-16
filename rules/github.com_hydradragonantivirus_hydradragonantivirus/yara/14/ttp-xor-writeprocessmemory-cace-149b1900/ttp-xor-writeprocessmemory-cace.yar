rule TTP_XOR_WriteProcessMemory_cace {
  strings:
    $key_cace = { 9d bc [2] af 9e [2] a9 ab [2] 87 ab [2] b8 b7 }

  condition:
    any of them
}