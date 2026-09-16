rule TTP_XOR_WriteProcessMemory_ebae {
  strings:
    $key_ebae = { bc dc [2] 8e fe [2] 88 cb [2] a6 cb [2] 99 d7 }

  condition:
    any of them
}