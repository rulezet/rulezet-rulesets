rule TTP_XOR_WriteProcessMemory_401b {
  strings:
    $key_401b = { 17 69 [2] 25 4b [2] 23 7e [2] 0d 7e [2] 32 62 }

  condition:
    any of them
}