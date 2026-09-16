rule TTP_XOR_WriteProcessMemory_498f {
  strings:
    $key_498f = { 1e fd [2] 2c df [2] 2a ea [2] 04 ea [2] 3b f6 }

  condition:
    any of them
}