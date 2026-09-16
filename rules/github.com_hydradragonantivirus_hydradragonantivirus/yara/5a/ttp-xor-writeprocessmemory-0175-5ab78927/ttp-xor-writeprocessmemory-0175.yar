rule TTP_XOR_WriteProcessMemory_0175 {
  strings:
    $key_0175 = { 56 07 [2] 64 25 [2] 62 10 [2] 4c 10 [2] 73 0c }

  condition:
    any of them
}