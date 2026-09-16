rule TTP_XOR_WriteProcessMemory_918f {
  strings:
    $key_918f = { c6 fd [2] f4 df [2] f2 ea [2] dc ea [2] e3 f6 }

  condition:
    any of them
}