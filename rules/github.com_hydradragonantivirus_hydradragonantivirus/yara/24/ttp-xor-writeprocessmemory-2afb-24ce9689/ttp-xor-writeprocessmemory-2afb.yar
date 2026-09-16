rule TTP_XOR_WriteProcessMemory_2afb {
  strings:
    $key_2afb = { 7d 89 [2] 4f ab [2] 49 9e [2] 67 9e [2] 58 82 }

  condition:
    any of them
}