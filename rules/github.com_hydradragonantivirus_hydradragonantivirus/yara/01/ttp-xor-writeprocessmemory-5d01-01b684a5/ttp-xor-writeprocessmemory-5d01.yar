rule TTP_XOR_WriteProcessMemory_5d01 {
  strings:
    $key_5d01 = { 0a 73 [2] 38 51 [2] 3e 64 [2] 10 64 [2] 2f 78 }

  condition:
    any of them
}