rule TTP_XOR_WriteProcessMemory_2b1b {
  strings:
    $key_2b1b = { 7c 69 [2] 4e 4b [2] 48 7e [2] 66 7e [2] 59 62 }

  condition:
    any of them
}