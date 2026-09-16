rule TTP_XOR_WriteProcessMemory_af8d {
  strings:
    $key_af8d = { f8 ff [2] ca dd [2] cc e8 [2] e2 e8 [2] dd f4 }

  condition:
    any of them
}