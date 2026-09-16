rule TTP_XOR_WriteProcessMemory_c8ae {
  strings:
    $key_c8ae = { 9f dc [2] ad fe [2] ab cb [2] 85 cb [2] ba d7 }

  condition:
    any of them
}