rule TTP_XOR_WriteProcessMemory_011d {
  strings:
    $key_011d = { 56 6f [2] 64 4d [2] 62 78 [2] 4c 78 [2] 73 64 }

  condition:
    any of them
}