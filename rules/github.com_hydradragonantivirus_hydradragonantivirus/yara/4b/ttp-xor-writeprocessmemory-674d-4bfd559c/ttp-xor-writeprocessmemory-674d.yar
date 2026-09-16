rule TTP_XOR_WriteProcessMemory_674d {
  strings:
    $key_674d = { 30 3f [2] 02 1d [2] 04 28 [2] 2a 28 [2] 15 34 }

  condition:
    any of them
}