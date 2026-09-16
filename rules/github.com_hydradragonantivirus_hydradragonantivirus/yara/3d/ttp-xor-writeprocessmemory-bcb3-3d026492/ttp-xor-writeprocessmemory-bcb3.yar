rule TTP_XOR_WriteProcessMemory_bcb3 {
  strings:
    $key_bcb3 = { eb c1 [2] d9 e3 [2] df d6 [2] f1 d6 [2] ce ca }

  condition:
    any of them
}