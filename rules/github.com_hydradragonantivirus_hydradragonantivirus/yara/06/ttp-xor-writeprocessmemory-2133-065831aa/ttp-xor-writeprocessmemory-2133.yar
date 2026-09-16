rule TTP_XOR_WriteProcessMemory_2133 {
  strings:
    $key_2133 = { 76 41 [2] 44 63 [2] 42 56 [2] 6c 56 [2] 53 4a }

  condition:
    any of them
}