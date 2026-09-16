rule TTP_XOR_WriteProcessMemory_2124 {
  strings:
    $key_2124 = { 76 56 [2] 44 74 [2] 42 41 [2] 6c 41 [2] 53 5d }

  condition:
    any of them
}