rule TTP_XOR_WriteProcessMemory_0933 {
  strings:
    $key_0933 = { 5e 41 [2] 6c 63 [2] 6a 56 [2] 44 56 [2] 7b 4a }

  condition:
    any of them
}