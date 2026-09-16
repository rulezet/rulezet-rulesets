rule TTP_XOR_WriteProcessMemory_9f88 {
  strings:
    $key_9f88 = { c8 fa [2] fa d8 [2] fc ed [2] d2 ed [2] ed f1 }

  condition:
    any of them
}