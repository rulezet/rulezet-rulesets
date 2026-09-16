rule TTP_XOR_WriteProcessMemory_cf86 {
  strings:
    $key_cf86 = { 98 f4 [2] aa d6 [2] ac e3 [2] 82 e3 [2] bd ff }

  condition:
    any of them
}