rule TTP_XOR_WriteProcessMemory_620d {
  strings:
    $key_620d = { 35 7f [2] 07 5d [2] 01 68 [2] 2f 68 [2] 10 74 }

  condition:
    any of them
}