rule TTP_XOR_WriteProcessMemory_1413 {
  strings:
    $key_1413 = { 43 61 [2] 71 43 [2] 77 76 [2] 59 76 [2] 66 6a }

  condition:
    any of them
}