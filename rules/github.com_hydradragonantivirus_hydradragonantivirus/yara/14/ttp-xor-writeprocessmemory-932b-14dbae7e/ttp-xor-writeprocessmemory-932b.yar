rule TTP_XOR_WriteProcessMemory_932b {
  strings:
    $key_932b = { c4 59 [2] f6 7b [2] f0 4e [2] de 4e [2] e1 52 }

  condition:
    any of them
}