rule TTP_XOR_WriteProcessMemory_4c01 {
  strings:
    $key_4c01 = { 1b 73 [2] 29 51 [2] 2f 64 [2] 01 64 [2] 3e 78 }

  condition:
    any of them
}