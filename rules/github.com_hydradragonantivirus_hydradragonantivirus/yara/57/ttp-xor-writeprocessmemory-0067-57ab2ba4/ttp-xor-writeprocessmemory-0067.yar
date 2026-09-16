rule TTP_XOR_WriteProcessMemory_0067 {
  strings:
    $key_0067 = { 57 15 [2] 65 37 [2] 63 02 [2] 4d 02 [2] 72 1e }

  condition:
    any of them
}