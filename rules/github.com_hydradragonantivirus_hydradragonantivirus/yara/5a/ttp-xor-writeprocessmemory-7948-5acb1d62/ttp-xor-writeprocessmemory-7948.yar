rule TTP_XOR_WriteProcessMemory_7948 {
  strings:
    $key_7948 = { 2e 3a [2] 1c 18 [2] 1a 2d [2] 34 2d [2] 0b 31 }

  condition:
    any of them
}