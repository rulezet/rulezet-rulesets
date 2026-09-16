rule TTP_XOR_WriteProcessMemory_ac88 {
  strings:
    $key_ac88 = { fb fa [2] c9 d8 [2] cf ed [2] e1 ed [2] de f1 }

  condition:
    any of them
}