rule TTP_XOR_WriteProcessMemory_617e {
  strings:
    $key_617e = { 36 0c [2] 04 2e [2] 02 1b [2] 2c 1b [2] 13 07 }

  condition:
    any of them
}