rule TTP_XOR_WriteProcessMemory_ce88 {
  strings:
    $key_ce88 = { 99 fa [2] ab d8 [2] ad ed [2] 83 ed [2] bc f1 }

  condition:
    any of them
}