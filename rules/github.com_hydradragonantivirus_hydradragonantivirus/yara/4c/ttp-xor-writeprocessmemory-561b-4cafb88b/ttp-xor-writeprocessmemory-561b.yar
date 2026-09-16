rule TTP_XOR_WriteProcessMemory_561b {
  strings:
    $key_561b = { 01 69 [2] 33 4b [2] 35 7e [2] 1b 7e [2] 24 62 }

  condition:
    any of them
}