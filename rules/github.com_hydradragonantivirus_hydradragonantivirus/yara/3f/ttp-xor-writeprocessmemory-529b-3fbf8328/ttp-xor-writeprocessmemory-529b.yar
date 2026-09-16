rule TTP_XOR_WriteProcessMemory_529b {
  strings:
    $key_529b = { 05 e9 [2] 37 cb [2] 31 fe [2] 1f fe [2] 20 e2 }

  condition:
    any of them
}