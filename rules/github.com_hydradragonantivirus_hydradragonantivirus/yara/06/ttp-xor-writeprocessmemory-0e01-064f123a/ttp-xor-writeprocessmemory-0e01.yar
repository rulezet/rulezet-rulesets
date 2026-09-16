rule TTP_XOR_WriteProcessMemory_0e01 {
  strings:
    $key_0e01 = { 59 73 [2] 6b 51 [2] 6d 64 [2] 43 64 [2] 7c 78 }

  condition:
    any of them
}