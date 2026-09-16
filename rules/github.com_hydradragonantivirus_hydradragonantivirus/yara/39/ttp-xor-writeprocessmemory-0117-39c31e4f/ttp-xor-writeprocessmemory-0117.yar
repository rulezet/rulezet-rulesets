rule TTP_XOR_WriteProcessMemory_0117 {
  strings:
    $key_0117 = { 56 65 [2] 64 47 [2] 62 72 [2] 4c 72 [2] 73 6e }

  condition:
    any of them
}