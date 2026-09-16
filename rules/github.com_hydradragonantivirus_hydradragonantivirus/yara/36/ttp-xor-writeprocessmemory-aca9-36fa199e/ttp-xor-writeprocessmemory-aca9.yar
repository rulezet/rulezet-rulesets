rule TTP_XOR_WriteProcessMemory_aca9 {
  strings:
    $key_aca9 = { fb db [2] c9 f9 [2] cf cc [2] e1 cc [2] de d0 }

  condition:
    any of them
}