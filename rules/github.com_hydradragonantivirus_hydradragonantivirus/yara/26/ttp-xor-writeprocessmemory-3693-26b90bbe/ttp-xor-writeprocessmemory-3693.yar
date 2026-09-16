rule TTP_XOR_WriteProcessMemory_3693 {
  strings:
    $key_3693 = { 61 e1 [2] 53 c3 [2] 55 f6 [2] 7b f6 [2] 44 ea }

  condition:
    any of them
}