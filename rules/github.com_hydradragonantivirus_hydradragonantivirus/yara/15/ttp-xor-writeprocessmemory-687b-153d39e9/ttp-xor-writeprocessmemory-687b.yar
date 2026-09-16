rule TTP_XOR_WriteProcessMemory_687b {
  strings:
    $key_687b = { 3f 09 [2] 0d 2b [2] 0b 1e [2] 25 1e [2] 1a 02 }

  condition:
    any of them
}