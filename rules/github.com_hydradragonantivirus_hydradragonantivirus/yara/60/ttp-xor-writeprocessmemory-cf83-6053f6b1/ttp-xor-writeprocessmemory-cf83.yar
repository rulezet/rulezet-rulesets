rule TTP_XOR_WriteProcessMemory_cf83 {
  strings:
    $key_cf83 = { 98 f1 [2] aa d3 [2] ac e6 [2] 82 e6 [2] bd fa }

  condition:
    any of them
}