rule TTP_XOR_WriteProcessMemory_8393 {
  strings:
    $key_8393 = { d4 e1 [2] e6 c3 [2] e0 f6 [2] ce f6 [2] f1 ea }

  condition:
    any of them
}