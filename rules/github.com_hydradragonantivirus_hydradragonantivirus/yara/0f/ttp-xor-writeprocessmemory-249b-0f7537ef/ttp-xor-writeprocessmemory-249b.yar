rule TTP_XOR_WriteProcessMemory_249b {
  strings:
    $key_249b = { 73 e9 [2] 41 cb [2] 47 fe [2] 69 fe [2] 56 e2 }

  condition:
    any of them
}