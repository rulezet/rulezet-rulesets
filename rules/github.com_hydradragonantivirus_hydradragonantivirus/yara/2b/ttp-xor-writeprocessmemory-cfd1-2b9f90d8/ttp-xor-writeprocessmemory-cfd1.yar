rule TTP_XOR_WriteProcessMemory_cfd1 {
  strings:
    $key_cfd1 = { 98 a3 [2] aa 81 [2] ac b4 [2] 82 b4 [2] bd a8 }

  condition:
    any of them
}