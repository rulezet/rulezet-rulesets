rule TTP_XOR_WriteProcessMemory_cdce {
  strings:
    $key_cdce = { 9a bc [2] a8 9e [2] ae ab [2] 80 ab [2] bf b7 }

  condition:
    any of them
}