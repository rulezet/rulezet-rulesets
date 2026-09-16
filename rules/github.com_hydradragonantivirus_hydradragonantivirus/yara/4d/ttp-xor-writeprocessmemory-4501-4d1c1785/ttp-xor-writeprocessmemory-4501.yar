rule TTP_XOR_WriteProcessMemory_4501 {
  strings:
    $key_4501 = { 12 73 [2] 20 51 [2] 26 64 [2] 08 64 [2] 37 78 }

  condition:
    any of them
}