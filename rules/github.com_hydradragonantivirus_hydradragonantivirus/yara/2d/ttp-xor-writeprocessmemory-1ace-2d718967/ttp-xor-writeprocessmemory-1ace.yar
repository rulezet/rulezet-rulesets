rule TTP_XOR_WriteProcessMemory_1ace {
  strings:
    $key_1ace = { 4d bc [2] 7f 9e [2] 79 ab [2] 57 ab [2] 68 b7 }

  condition:
    any of them
}