rule TTP_XOR_WriteProcessMemory_5dac {
  strings:
    $key_5dac = { 0a de [2] 38 fc [2] 3e c9 [2] 10 c9 [2] 2f d5 }

  condition:
    any of them
}