rule TTP_XOR_WriteProcessMemory_687c {
  strings:
    $key_687c = { 3f 0e [2] 0d 2c [2] 0b 19 [2] 25 19 [2] 1a 05 }

  condition:
    any of them
}