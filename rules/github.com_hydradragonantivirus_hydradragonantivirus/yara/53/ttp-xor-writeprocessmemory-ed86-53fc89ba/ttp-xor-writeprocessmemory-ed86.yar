rule TTP_XOR_WriteProcessMemory_ed86 {
  strings:
    $key_ed86 = { ba f4 [2] 88 d6 [2] 8e e3 [2] a0 e3 [2] 9f ff }

  condition:
    any of them
}