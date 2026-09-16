rule TTP_XOR_WriteProcessMemory_2693 {
  strings:
    $key_2693 = { 71 e1 [2] 43 c3 [2] 45 f6 [2] 6b f6 [2] 54 ea }

  condition:
    any of them
}