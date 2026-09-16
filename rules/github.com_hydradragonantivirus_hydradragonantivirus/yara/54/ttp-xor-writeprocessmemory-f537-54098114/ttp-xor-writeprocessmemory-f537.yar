rule TTP_XOR_WriteProcessMemory_f537 {
  strings:
    $key_f537 = { a2 45 [2] 90 67 [2] 96 52 [2] b8 52 [2] 87 4e }

  condition:
    any of them
}