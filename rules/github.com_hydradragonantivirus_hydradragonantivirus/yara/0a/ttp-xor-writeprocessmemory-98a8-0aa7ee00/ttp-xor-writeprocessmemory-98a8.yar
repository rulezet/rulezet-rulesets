rule TTP_XOR_WriteProcessMemory_98a8 {
  strings:
    $key_98a8 = { cf da [2] fd f8 [2] fb cd [2] d5 cd [2] ea d1 }

  condition:
    any of them
}