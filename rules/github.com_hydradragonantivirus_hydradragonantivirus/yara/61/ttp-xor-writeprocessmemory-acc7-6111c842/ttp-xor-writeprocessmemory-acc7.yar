rule TTP_XOR_WriteProcessMemory_acc7 {
  strings:
    $key_acc7 = { fb b5 [2] c9 97 [2] cf a2 [2] e1 a2 [2] de be }

  condition:
    any of them
}