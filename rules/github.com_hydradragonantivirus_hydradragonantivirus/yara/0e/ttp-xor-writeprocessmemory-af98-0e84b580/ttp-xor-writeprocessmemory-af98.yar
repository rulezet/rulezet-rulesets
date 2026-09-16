rule TTP_XOR_WriteProcessMemory_af98 {
  strings:
    $key_af98 = { f8 ea [2] ca c8 [2] cc fd [2] e2 fd [2] dd e1 }

  condition:
    any of them
}