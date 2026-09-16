rule TTP_XOR_WriteProcessMemory_b262 {
  strings:
    $key_b262 = { e5 10 [2] d7 32 [2] d1 07 [2] ff 07 [2] c0 1b }

  condition:
    any of them
}