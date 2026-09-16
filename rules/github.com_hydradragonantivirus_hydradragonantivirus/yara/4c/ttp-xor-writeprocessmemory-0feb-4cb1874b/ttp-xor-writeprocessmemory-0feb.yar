rule TTP_XOR_WriteProcessMemory_0feb {
  strings:
    $key_0feb = { 58 99 [2] 6a bb [2] 6c 8e [2] 42 8e [2] 7d 92 }

  condition:
    any of them
}