rule TTP_XOR_WriteProcessMemory_9fb8 {
  strings:
    $key_9fb8 = { c8 ca [2] fa e8 [2] fc dd [2] d2 dd [2] ed c1 }

  condition:
    any of them
}