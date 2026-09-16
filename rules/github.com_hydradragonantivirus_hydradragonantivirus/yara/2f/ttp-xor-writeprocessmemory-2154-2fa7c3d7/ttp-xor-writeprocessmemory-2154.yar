rule TTP_XOR_WriteProcessMemory_2154 {
  strings:
    $key_2154 = { 76 26 [2] 44 04 [2] 42 31 [2] 6c 31 [2] 53 2d }

  condition:
    any of them
}