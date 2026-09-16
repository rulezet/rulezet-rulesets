rule TTP_XOR_WriteProcessMemory_0113 {
  strings:
    $key_0113 = { 56 61 [2] 64 43 [2] 62 76 [2] 4c 76 [2] 73 6a }

  condition:
    any of them
}