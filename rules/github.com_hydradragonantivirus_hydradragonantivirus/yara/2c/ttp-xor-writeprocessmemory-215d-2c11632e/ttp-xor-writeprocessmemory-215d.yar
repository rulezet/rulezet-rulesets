rule TTP_XOR_WriteProcessMemory_215d {
  strings:
    $key_215d = { 76 2f [2] 44 0d [2] 42 38 [2] 6c 38 [2] 53 24 }

  condition:
    any of them
}