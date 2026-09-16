rule TTP_XOR_WriteProcessMemory_3697 {
  strings:
    $key_3697 = { 61 e5 [2] 53 c7 [2] 55 f2 [2] 7b f2 [2] 44 ee }

  condition:
    any of them
}