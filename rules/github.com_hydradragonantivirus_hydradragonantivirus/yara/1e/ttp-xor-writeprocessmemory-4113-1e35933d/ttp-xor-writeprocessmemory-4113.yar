rule TTP_XOR_WriteProcessMemory_4113 {
  strings:
    $key_4113 = { 16 61 [2] 24 43 [2] 22 76 [2] 0c 76 [2] 33 6a }

  condition:
    any of them
}