rule TTP_XOR_WriteProcessMemory_7feb {
  strings:
    $key_7feb = { 28 99 [2] 1a bb [2] 1c 8e [2] 32 8e [2] 0d 92 }

  condition:
    any of them
}