rule TTP_XOR_WriteProcessMemory_91eb {
  strings:
    $key_91eb = { c6 99 [2] f4 bb [2] f2 8e [2] dc 8e [2] e3 92 }

  condition:
    any of them
}