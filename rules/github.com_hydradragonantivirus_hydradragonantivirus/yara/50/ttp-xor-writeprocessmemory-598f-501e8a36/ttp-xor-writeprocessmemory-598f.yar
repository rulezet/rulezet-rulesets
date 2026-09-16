rule TTP_XOR_WriteProcessMemory_598f {
  strings:
    $key_598f = { 0e fd [2] 3c df [2] 3a ea [2] 14 ea [2] 2b f6 }

  condition:
    any of them
}