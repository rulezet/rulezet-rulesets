rule TTP_XOR_WriteProcessMemory_2134 {
  strings:
    $key_2134 = { 76 46 [2] 44 64 [2] 42 51 [2] 6c 51 [2] 53 4d }

  condition:
    any of them
}