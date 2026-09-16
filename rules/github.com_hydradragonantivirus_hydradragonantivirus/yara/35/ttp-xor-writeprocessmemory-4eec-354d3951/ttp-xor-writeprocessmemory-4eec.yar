rule TTP_XOR_WriteProcessMemory_4eec {
  strings:
    $key_4eec = { 19 9e [2] 2b bc [2] 2d 89 [2] 03 89 [2] 3c 95 }

  condition:
    any of them
}