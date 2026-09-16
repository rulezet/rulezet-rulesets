rule TTP_XOR_WriteProcessMemory_e164 {
  strings:
    $key_e164 = { b6 16 [2] 84 34 [2] 82 01 [2] ac 01 [2] 93 1d }

  condition:
    any of them
}