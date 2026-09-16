rule TTP_XOR_WriteProcessMemory_0537 {
  strings:
    $key_0537 = { 52 45 [2] 60 67 [2] 66 52 [2] 48 52 [2] 77 4e }

  condition:
    any of them
}