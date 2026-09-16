rule TTP_XOR_WriteProcessMemory_1dac {
  strings:
    $key_1dac = { 4a de [2] 78 fc [2] 7e c9 [2] 50 c9 [2] 6f d5 }

  condition:
    any of them
}