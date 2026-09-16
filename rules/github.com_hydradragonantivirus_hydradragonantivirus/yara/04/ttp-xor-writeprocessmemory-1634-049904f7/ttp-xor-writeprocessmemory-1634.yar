rule TTP_XOR_WriteProcessMemory_1634 {
  strings:
    $key_1634 = { 41 46 [2] 73 64 [2] 75 51 [2] 5b 51 [2] 64 4d }

  condition:
    any of them
}