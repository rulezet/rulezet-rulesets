rule TTP_XOR_WriteProcessMemory_c9d9 {
  strings:
    $key_c9d9 = { 9e ab [2] ac 89 [2] aa bc [2] 84 bc [2] bb a0 }

  condition:
    any of them
}