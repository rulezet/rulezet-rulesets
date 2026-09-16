rule TTP_XOR_WriteProcessMemory_712d {
  strings:
    $key_712d = { 26 5f [2] 14 7d [2] 12 48 [2] 3c 48 [2] 03 54 }

  condition:
    any of them
}