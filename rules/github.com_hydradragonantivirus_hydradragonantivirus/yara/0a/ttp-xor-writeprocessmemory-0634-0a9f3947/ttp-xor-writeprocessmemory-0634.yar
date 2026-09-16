rule TTP_XOR_WriteProcessMemory_0634 {
  strings:
    $key_0634 = { 51 46 [2] 63 64 [2] 65 51 [2] 4b 51 [2] 74 4d }

  condition:
    any of them
}