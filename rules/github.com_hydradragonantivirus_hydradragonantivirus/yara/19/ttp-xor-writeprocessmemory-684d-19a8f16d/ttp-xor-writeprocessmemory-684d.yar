rule TTP_XOR_WriteProcessMemory_684d {
  strings:
    $key_684d = { 3f 3f [2] 0d 1d [2] 0b 28 [2] 25 28 [2] 1a 34 }

  condition:
    any of them
}