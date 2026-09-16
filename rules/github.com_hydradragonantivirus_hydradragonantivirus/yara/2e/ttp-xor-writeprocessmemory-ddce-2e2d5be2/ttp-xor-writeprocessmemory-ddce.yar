rule TTP_XOR_WriteProcessMemory_ddce {
  strings:
    $key_ddce = { 8a bc [2] b8 9e [2] be ab [2] 90 ab [2] af b7 }

  condition:
    any of them
}