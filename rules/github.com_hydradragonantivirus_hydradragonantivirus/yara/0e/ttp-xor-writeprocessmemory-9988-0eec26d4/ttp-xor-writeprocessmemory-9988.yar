rule TTP_XOR_WriteProcessMemory_9988 {
  strings:
    $key_9988 = { ce fa [2] fc d8 [2] fa ed [2] d4 ed [2] eb f1 }

  condition:
    any of them
}