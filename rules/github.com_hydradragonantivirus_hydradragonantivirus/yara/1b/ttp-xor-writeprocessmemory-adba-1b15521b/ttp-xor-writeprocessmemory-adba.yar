rule TTP_XOR_WriteProcessMemory_adba {
  strings:
    $key_adba = { fa c8 [2] c8 ea [2] ce df [2] e0 df [2] df c3 }

  condition:
    any of them
}