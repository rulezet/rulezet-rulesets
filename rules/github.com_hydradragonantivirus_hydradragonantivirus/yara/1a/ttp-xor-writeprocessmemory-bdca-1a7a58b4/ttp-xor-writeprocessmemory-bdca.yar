rule TTP_XOR_WriteProcessMemory_bdca {
  strings:
    $key_bdca = { ea b8 [2] d8 9a [2] de af [2] f0 af [2] cf b3 }

  condition:
    any of them
}