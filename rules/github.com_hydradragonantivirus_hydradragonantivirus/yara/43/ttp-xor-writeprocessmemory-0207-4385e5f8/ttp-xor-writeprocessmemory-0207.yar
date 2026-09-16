rule TTP_XOR_WriteProcessMemory_0207 {
  strings:
    $key_0207 = { 55 75 [2] 67 57 [2] 61 62 [2] 4f 62 [2] 70 7e }

  condition:
    any of them
}