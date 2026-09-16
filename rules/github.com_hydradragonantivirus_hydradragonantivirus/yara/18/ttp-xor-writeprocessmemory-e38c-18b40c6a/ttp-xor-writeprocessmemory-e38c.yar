rule TTP_XOR_WriteProcessMemory_e38c {
  strings:
    $key_e38c = { b4 fe [2] 86 dc [2] 80 e9 [2] ae e9 [2] 91 f5 }

  condition:
    any of them
}