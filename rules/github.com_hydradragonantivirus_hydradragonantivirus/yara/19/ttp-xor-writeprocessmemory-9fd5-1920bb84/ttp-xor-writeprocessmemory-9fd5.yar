rule TTP_XOR_WriteProcessMemory_9fd5 {
  strings:
    $key_9fd5 = { c8 a7 [2] fa 85 [2] fc b0 [2] d2 b0 [2] ed ac }

  condition:
    any of them
}