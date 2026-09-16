rule TTP_XOR_WriteProcessMemory_3201 {
  strings:
    $key_3201 = { 65 73 [2] 57 51 [2] 51 64 [2] 7f 64 [2] 40 78 }

  condition:
    any of them
}