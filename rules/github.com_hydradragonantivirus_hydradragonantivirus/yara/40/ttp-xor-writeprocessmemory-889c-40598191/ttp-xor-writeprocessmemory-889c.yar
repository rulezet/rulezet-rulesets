rule TTP_XOR_WriteProcessMemory_889c {
  strings:
    $key_889c = { df ee [2] ed cc [2] eb f9 [2] c5 f9 [2] fa e5 }

  condition:
    any of them
}