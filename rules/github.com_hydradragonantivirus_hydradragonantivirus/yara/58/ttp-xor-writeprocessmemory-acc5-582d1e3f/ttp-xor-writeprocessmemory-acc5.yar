rule TTP_XOR_WriteProcessMemory_acc5 {
  strings:
    $key_acc5 = { fb b7 [2] c9 95 [2] cf a0 [2] e1 a0 [2] de bc }

  condition:
    any of them
}