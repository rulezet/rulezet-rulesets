rule TTP_XOR_WriteProcessMemory_0337 {
  strings:
    $key_0337 = { 54 45 [2] 66 67 [2] 60 52 [2] 4e 52 [2] 71 4e }

  condition:
    any of them
}