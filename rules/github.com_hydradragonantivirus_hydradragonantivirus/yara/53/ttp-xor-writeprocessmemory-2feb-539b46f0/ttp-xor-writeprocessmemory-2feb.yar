rule TTP_XOR_WriteProcessMemory_2feb {
  strings:
    $key_2feb = { 78 99 [2] 4a bb [2] 4c 8e [2] 62 8e [2] 5d 92 }

  condition:
    any of them
}