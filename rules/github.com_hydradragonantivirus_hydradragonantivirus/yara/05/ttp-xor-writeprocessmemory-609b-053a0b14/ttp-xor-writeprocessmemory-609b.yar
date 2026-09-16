rule TTP_XOR_WriteProcessMemory_609b {
  strings:
    $key_609b = { 37 e9 [2] 05 cb [2] 03 fe [2] 2d fe [2] 12 e2 }

  condition:
    any of them
}