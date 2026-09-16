rule TTP_XOR_WriteProcessMemory_6dce {
  strings:
    $key_6dce = { 3a bc [2] 08 9e [2] 0e ab [2] 20 ab [2] 1f b7 }

  condition:
    any of them
}