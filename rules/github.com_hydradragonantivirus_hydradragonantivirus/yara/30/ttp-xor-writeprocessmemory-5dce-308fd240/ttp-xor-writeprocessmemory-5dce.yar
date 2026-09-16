rule TTP_XOR_WriteProcessMemory_5dce {
  strings:
    $key_5dce = { 0a bc [2] 38 9e [2] 3e ab [2] 10 ab [2] 2f b7 }

  condition:
    any of them
}