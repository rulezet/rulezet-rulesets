rule TTP_XOR_WriteProcessMemory_aa88 {
  strings:
    $key_aa88 = { fd fa [2] cf d8 [2] c9 ed [2] e7 ed [2] d8 f1 }

  condition:
    any of them
}