rule TTP_XOR_WriteProcessMemory_e888 {
  strings:
    $key_e888 = { bf fa [2] 8d d8 [2] 8b ed [2] a5 ed [2] 9a f1 }

  condition:
    any of them
}