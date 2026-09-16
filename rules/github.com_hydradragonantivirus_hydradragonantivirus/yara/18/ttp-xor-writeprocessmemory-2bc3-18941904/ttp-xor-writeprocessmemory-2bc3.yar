rule TTP_XOR_WriteProcessMemory_2bc3 {
  strings:
    $key_2bc3 = { 7c b1 [2] 4e 93 [2] 48 a6 [2] 66 a6 [2] 59 ba }

  condition:
    any of them
}