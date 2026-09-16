rule TTP_XOR_WriteProcessMemory_33dd {
  strings:
    $key_33dd = { 64 af [2] 56 8d [2] 50 b8 [2] 7e b8 [2] 41 a4 }

  condition:
    any of them
}