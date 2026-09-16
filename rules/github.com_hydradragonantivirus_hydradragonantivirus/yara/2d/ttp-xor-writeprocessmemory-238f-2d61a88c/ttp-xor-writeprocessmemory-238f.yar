rule TTP_XOR_WriteProcessMemory_238f {
  strings:
    $key_238f = { 74 fd [2] 46 df [2] 40 ea [2] 6e ea [2] 51 f6 }

  condition:
    any of them
}