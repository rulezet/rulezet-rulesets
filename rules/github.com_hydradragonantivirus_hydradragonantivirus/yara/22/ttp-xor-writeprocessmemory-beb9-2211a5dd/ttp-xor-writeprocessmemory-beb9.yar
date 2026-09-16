rule TTP_XOR_WriteProcessMemory_beb9 {
  strings:
    $key_beb9 = { e9 cb [2] db e9 [2] dd dc [2] f3 dc [2] cc c0 }

  condition:
    any of them
}