rule TTP_XOR_WriteProcessMemory_0901 {
  strings:
    $key_0901 = { 5e 73 [2] 6c 51 [2] 6a 64 [2] 44 64 [2] 7b 78 }

  condition:
    any of them
}