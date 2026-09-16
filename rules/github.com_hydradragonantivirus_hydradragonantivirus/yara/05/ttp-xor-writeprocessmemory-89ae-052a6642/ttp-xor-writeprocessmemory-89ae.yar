rule TTP_XOR_WriteProcessMemory_89ae {
  strings:
    $key_89ae = { de dc [2] ec fe [2] ea cb [2] c4 cb [2] fb d7 }

  condition:
    any of them
}