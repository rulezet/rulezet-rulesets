rule TTP_XOR_WriteProcessMemory_1feb {
  strings:
    $key_1feb = { 48 99 [2] 7a bb [2] 7c 8e [2] 52 8e [2] 6d 92 }

  condition:
    any of them
}