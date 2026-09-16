rule TTP_XOR_WriteProcessMemory_938b {
  strings:
    $key_938b = { c4 f9 [2] f6 db [2] f0 ee [2] de ee [2] e1 f2 }

  condition:
    any of them
}