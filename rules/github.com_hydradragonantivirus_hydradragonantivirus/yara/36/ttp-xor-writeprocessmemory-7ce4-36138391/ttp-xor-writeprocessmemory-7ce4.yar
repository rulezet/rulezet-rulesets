rule TTP_XOR_WriteProcessMemory_7ce4 {
  strings:
    $key_7ce4 = { 2b 96 [2] 19 b4 [2] 1f 81 [2] 31 81 [2] 0e 9d }

  condition:
    any of them
}