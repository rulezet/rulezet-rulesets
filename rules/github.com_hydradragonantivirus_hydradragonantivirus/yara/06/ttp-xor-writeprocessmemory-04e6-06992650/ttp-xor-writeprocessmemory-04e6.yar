rule TTP_XOR_WriteProcessMemory_04e6 {
  strings:
    $key_04e6 = { 53 94 [2] 61 b6 [2] 67 83 [2] 49 83 [2] 76 9f }

  condition:
    any of them
}