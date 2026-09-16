rule TTP_XOR_WriteProcessMemory_4201 {
  strings:
    $key_4201 = { 15 73 [2] 27 51 [2] 21 64 [2] 0f 64 [2] 30 78 }

  condition:
    any of them
}