rule TTP_XOR_WriteProcessMemory_99b8 {
  strings:
    $key_99b8 = { ce ca [2] fc e8 [2] fa dd [2] d4 dd [2] eb c1 }

  condition:
    any of them
}