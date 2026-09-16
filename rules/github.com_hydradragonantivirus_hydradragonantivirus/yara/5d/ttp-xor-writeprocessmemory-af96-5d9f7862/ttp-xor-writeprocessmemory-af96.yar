rule TTP_XOR_WriteProcessMemory_af96 {
  strings:
    $key_af96 = { f8 e4 [2] ca c6 [2] cc f3 [2] e2 f3 [2] dd ef }

  condition:
    any of them
}