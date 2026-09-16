rule TTP_XOR_WriteProcessMemory_7c01 {
  strings:
    $key_7c01 = { 2b 73 [2] 19 51 [2] 1f 64 [2] 31 64 [2] 0e 78 }

  condition:
    any of them
}