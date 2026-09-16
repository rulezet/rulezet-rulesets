rule TTP_XOR_WriteProcessMemory_adad {
  strings:
    $key_adad = { fa df [2] c8 fd [2] ce c8 [2] e0 c8 [2] df d4 }

  condition:
    any of them
}