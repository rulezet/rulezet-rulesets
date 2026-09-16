rule TTP_XOR_WriteProcessMemory_d693 {
  strings:
    $key_d693 = { 81 e1 [2] b3 c3 [2] b5 f6 [2] 9b f6 [2] a4 ea }

  condition:
    any of them
}