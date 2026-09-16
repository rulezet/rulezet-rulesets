rule TTP_XOR_WriteProcessMemory_a9ae {
  strings:
    $key_a9ae = { fe dc [2] cc fe [2] ca cb [2] e4 cb [2] db d7 }

  condition:
    any of them
}