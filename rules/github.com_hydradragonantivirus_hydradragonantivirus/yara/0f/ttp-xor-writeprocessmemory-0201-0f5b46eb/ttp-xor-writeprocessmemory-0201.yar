rule TTP_XOR_WriteProcessMemory_0201 {
  strings:
    $key_0201 = { 55 73 [2] 67 51 [2] 61 64 [2] 4f 64 [2] 70 78 }

  condition:
    any of them
}