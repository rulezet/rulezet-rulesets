rule TTP_XOR_WriteProcessMemory_fcce {
  strings:
    $key_fcce = { ab bc [2] 99 9e [2] 9f ab [2] b1 ab [2] 8e b7 }

  condition:
    any of them
}