rule TTP_XOR_WriteProcessMemory_adce {
  strings:
    $key_adce = { fa bc [2] c8 9e [2] ce ab [2] e0 ab [2] df b7 }

  condition:
    any of them
}