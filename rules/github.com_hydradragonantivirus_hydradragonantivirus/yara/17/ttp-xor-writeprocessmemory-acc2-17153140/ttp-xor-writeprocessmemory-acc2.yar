rule TTP_XOR_WriteProcessMemory_acc2 {
  strings:
    $key_acc2 = { fb b0 [2] c9 92 [2] cf a7 [2] e1 a7 [2] de bb }

  condition:
    any of them
}