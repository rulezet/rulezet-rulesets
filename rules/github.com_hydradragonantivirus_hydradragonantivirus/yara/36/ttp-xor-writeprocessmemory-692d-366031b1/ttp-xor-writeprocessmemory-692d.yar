rule TTP_XOR_WriteProcessMemory_692d {
  strings:
    $key_692d = { 3e 5f [2] 0c 7d [2] 0a 48 [2] 24 48 [2] 1b 54 }

  condition:
    any of them
}