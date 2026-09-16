rule TTP_XOR_WriteProcessMemory_deab {
  strings:
    $key_deab = { 89 d9 [2] bb fb [2] bd ce [2] 93 ce [2] ac d2 }

  condition:
    any of them
}