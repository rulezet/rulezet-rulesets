rule TTP_XOR_WriteProcessMemory_acc8 {
  strings:
    $key_acc8 = { fb ba [2] c9 98 [2] cf ad [2] e1 ad [2] de b1 }

  condition:
    any of them
}