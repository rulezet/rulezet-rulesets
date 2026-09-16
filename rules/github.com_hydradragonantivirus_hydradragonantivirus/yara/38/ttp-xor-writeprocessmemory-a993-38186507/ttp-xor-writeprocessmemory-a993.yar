rule TTP_XOR_WriteProcessMemory_a993 {
  strings:
    $key_a993 = { fe e1 [2] cc c3 [2] ca f6 [2] e4 f6 [2] db ea }

  condition:
    any of them
}