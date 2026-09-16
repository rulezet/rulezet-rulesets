rule TTP_XOR_WriteProcessMemory_9fe5 {
  strings:
    $key_9fe5 = { c8 97 [2] fa b5 [2] fc 80 [2] d2 80 [2] ed 9c }

  condition:
    any of them
}