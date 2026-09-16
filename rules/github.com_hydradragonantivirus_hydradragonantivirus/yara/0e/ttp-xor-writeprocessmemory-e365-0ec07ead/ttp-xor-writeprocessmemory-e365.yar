rule TTP_XOR_WriteProcessMemory_e365 {
  strings:
    $key_e365 = { b4 17 [2] 86 35 [2] 80 00 [2] ae 00 [2] 91 1c }

  condition:
    any of them
}