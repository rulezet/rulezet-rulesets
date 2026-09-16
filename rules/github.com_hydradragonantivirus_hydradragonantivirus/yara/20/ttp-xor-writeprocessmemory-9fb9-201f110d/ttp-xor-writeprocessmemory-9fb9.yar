rule TTP_XOR_WriteProcessMemory_9fb9 {
  strings:
    $key_9fb9 = { c8 cb [2] fa e9 [2] fc dc [2] d2 dc [2] ed c0 }

  condition:
    any of them
}