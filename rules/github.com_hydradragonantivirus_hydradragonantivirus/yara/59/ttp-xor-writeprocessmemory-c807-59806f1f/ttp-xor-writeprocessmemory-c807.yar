rule TTP_XOR_WriteProcessMemory_c807 {
  strings:
    $key_c807 = { 9f 75 [2] ad 57 [2] ab 62 [2] 85 62 [2] ba 7e }

  condition:
    any of them
}