rule TTP_XOR_WriteProcessMemory_b538 {
  strings:
    $key_b538 = { e2 4a [2] d0 68 [2] d6 5d [2] f8 5d [2] c7 41 }

  condition:
    any of them
}