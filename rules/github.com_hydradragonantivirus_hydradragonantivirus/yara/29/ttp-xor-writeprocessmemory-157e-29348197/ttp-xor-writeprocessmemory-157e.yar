rule TTP_XOR_WriteProcessMemory_157e {
  strings:
    $key_157e = { 42 0c [2] 70 2e [2] 76 1b [2] 58 1b [2] 67 07 }

  condition:
    any of them
}