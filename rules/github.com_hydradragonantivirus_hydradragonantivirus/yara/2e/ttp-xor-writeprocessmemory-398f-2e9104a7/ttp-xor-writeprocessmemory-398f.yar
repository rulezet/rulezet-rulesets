rule TTP_XOR_WriteProcessMemory_398f {
  strings:
    $key_398f = { 6e fd [2] 5c df [2] 5a ea [2] 74 ea [2] 4b f6 }

  condition:
    any of them
}