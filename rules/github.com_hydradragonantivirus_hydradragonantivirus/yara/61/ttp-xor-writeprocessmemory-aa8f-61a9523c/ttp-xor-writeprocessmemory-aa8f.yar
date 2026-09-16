rule TTP_XOR_WriteProcessMemory_aa8f {
  strings:
    $key_aa8f = { fd fd [2] cf df [2] c9 ea [2] e7 ea [2] d8 f6 }

  condition:
    any of them
}