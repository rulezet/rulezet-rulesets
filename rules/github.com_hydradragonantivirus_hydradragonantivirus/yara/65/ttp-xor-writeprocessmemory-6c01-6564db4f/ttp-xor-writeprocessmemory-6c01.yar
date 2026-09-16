rule TTP_XOR_WriteProcessMemory_6c01 {
  strings:
    $key_6c01 = { 3b 73 [2] 09 51 [2] 0f 64 [2] 21 64 [2] 1e 78 }

  condition:
    any of them
}