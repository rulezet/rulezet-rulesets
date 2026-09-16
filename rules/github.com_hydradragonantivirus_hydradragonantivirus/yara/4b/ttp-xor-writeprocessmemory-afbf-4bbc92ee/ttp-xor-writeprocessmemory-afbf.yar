rule TTP_XOR_WriteProcessMemory_afbf {
  strings:
    $key_afbf = { f8 cd [2] ca ef [2] cc da [2] e2 da [2] dd c6 }

  condition:
    any of them
}