rule TTP_XOR_WriteProcessMemory_0232 {
  strings:
    $key_0232 = { 55 40 [2] 67 62 [2] 61 57 [2] 4f 57 [2] 70 4b }

  condition:
    any of them
}