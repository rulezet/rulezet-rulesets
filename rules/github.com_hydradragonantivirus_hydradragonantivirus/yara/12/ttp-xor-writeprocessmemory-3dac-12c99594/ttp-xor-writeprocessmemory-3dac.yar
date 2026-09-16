rule TTP_XOR_WriteProcessMemory_3dac {
  strings:
    $key_3dac = { 6a de [2] 58 fc [2] 5e c9 [2] 70 c9 [2] 4f d5 }

  condition:
    any of them
}