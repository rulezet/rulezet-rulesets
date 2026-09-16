rule TTP_XOR_WriteProcessMemory_04e4 {
  strings:
    $key_04e4 = { 53 96 [2] 61 b4 [2] 67 81 [2] 49 81 [2] 76 9d }

  condition:
    any of them
}