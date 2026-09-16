rule TTP_XOR_WriteProcessMemory_7928 {
  strings:
    $key_7928 = { 2e 5a [2] 1c 78 [2] 1a 4d [2] 34 4d [2] 0b 51 }

  condition:
    any of them
}