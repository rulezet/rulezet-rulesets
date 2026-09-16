rule TTP_XOR_WriteProcessMemory_669b {
  strings:
    $key_669b = { 31 e9 [2] 03 cb [2] 05 fe [2] 2b fe [2] 14 e2 }

  condition:
    any of them
}