rule TTP_XOR_WriteProcessMemory_542d {
  strings:
    $key_542d = { 03 5f [2] 31 7d [2] 37 48 [2] 19 48 [2] 26 54 }

  condition:
    any of them
}