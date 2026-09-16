rule TTP_XOR_WriteProcessMemory_069b {
  strings:
    $key_069b = { 51 e9 [2] 63 cb [2] 65 fe [2] 4b fe [2] 74 e2 }

  condition:
    any of them
}