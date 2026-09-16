rule TTP_XOR_WriteProcessMemory_3e64 {
  strings:
    $key_3e64 = { 69 16 [2] 5b 34 [2] 5d 01 [2] 73 01 [2] 4c 1d }

  condition:
    any of them
}