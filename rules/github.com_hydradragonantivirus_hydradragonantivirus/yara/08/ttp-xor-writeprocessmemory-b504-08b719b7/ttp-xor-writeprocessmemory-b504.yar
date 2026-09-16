rule TTP_XOR_WriteProcessMemory_b504 {
  strings:
    $key_b504 = { e2 76 [2] d0 54 [2] d6 61 [2] f8 61 [2] c7 7d }

  condition:
    any of them
}