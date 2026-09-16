rule TTP_XOR_WriteProcessMemory_7de3 {
  strings:
    $key_7de3 = { 2a 91 [2] 18 b3 [2] 1e 86 [2] 30 86 [2] 0f 9a }

  condition:
    any of them
}