rule TTP_XOR_WriteProcessMemory_e430 {
  strings:
    $key_e430 = { b3 42 [2] 81 60 [2] 87 55 [2] a9 55 [2] 96 49 }

  condition:
    any of them
}