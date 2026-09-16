rule TTP_XOR_WriteProcessMemory_6952 {
  strings:
    $key_6952 = { 3e 20 [2] 0c 02 [2] 0a 37 [2] 24 37 [2] 1b 2b }

  condition:
    any of them
}