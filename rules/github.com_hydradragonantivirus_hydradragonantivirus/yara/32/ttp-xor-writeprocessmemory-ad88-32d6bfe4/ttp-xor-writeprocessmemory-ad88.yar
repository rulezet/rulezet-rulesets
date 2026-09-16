rule TTP_XOR_WriteProcessMemory_ad88 {
  strings:
    $key_ad88 = { fa fa [2] c8 d8 [2] ce ed [2] e0 ed [2] df f1 }

  condition:
    any of them
}