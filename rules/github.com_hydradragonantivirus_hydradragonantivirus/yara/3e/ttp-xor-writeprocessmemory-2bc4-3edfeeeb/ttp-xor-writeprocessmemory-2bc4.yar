rule TTP_XOR_WriteProcessMemory_2bc4 {
  strings:
    $key_2bc4 = { 7c b6 [2] 4e 94 [2] 48 a1 [2] 66 a1 [2] 59 bd }

  condition:
    any of them
}