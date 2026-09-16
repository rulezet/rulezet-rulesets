rule TTP_XOR_WriteProcessMemory_dc9b {
  strings:
    $key_dc9b = { 8b e9 [2] b9 cb [2] bf fe [2] 91 fe [2] ae e2 }

  condition:
    any of them
}