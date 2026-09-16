rule TTP_XOR_WriteProcessMemory_2bc5 {
  strings:
    $key_2bc5 = { 7c b7 [2] 4e 95 [2] 48 a0 [2] 66 a0 [2] 59 bc }

  condition:
    any of them
}