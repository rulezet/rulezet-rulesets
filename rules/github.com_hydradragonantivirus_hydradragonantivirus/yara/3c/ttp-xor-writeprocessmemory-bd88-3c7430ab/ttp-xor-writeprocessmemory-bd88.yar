rule TTP_XOR_WriteProcessMemory_bd88 {
  strings:
    $key_bd88 = { ea fa [2] d8 d8 [2] de ed [2] f0 ed [2] cf f1 }

  condition:
    any of them
}