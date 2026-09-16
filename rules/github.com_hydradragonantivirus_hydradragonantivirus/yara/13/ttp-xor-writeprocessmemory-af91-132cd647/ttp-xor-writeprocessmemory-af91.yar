rule TTP_XOR_WriteProcessMemory_af91 {
  strings:
    $key_af91 = { f8 e3 [2] ca c1 [2] cc f4 [2] e2 f4 [2] dd e8 }

  condition:
    any of them
}