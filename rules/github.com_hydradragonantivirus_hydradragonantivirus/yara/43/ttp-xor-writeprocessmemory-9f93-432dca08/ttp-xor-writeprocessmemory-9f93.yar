rule TTP_XOR_WriteProcessMemory_9f93 {
  strings:
    $key_9f93 = { c8 e1 [2] fa c3 [2] fc f6 [2] d2 f6 [2] ed ea }

  condition:
    any of them
}