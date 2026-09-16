rule TTP_XOR_WriteProcessMemory_4b35 {
  strings:
    $key_4b35 = { 1c 47 [2] 2e 65 [2] 28 50 [2] 06 50 [2] 39 4c }

  condition:
    any of them
}