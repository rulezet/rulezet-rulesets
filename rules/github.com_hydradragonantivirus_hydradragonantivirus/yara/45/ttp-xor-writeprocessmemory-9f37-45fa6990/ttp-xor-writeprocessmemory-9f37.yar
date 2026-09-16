rule TTP_XOR_WriteProcessMemory_9f37 {
  strings:
    $key_9f37 = { c8 45 [2] fa 67 [2] fc 52 [2] d2 52 [2] ed 4e }

  condition:
    any of them
}