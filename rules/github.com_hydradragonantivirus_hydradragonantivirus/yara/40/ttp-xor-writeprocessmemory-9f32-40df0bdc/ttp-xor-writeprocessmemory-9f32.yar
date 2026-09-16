rule TTP_XOR_WriteProcessMemory_9f32 {
  strings:
    $key_9f32 = { c8 40 [2] fa 62 [2] fc 57 [2] d2 57 [2] ed 4b }

  condition:
    any of them
}