rule TTP_XOR_WriteProcessMemory_9493 {
  strings:
    $key_9493 = { c3 e1 [2] f1 c3 [2] f7 f6 [2] d9 f6 [2] e6 ea }

  condition:
    any of them
}