rule TTP_XOR_WriteProcessMemory_221b {
  strings:
    $key_221b = { 75 69 [2] 47 4b [2] 41 7e [2] 6f 7e [2] 50 62 }

  condition:
    any of them
}