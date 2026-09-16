rule TTP_XOR_WriteProcessMemory_bb93 {
  strings:
    $key_bb93 = { ec e1 [2] de c3 [2] d8 f6 [2] f6 f6 [2] c9 ea }

  condition:
    any of them
}