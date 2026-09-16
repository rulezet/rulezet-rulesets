rule TTP_XOR_WriteProcessMemory_b8b5 {
  strings:
    $key_b8b5 = { ef c7 [2] dd e5 [2] db d0 [2] f5 d0 [2] ca cc }

  condition:
    any of them
}