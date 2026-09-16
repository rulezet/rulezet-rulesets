rule TTP_XOR_WriteProcessMemory_afa3 {
  strings:
    $key_afa3 = { f8 d1 [2] ca f3 [2] cc c6 [2] e2 c6 [2] dd da }

  condition:
    any of them
}