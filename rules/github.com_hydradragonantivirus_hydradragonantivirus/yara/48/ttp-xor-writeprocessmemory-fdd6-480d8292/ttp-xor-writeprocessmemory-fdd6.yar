rule TTP_XOR_WriteProcessMemory_fdd6 {
  strings:
    $key_fdd6 = { aa a4 [2] 98 86 [2] 9e b3 [2] b0 b3 [2] 8f af }

  condition:
    any of them
}