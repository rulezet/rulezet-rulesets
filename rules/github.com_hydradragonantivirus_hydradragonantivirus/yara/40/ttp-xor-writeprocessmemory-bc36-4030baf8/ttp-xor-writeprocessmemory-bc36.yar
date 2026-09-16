rule TTP_XOR_WriteProcessMemory_bc36 {
  strings:
    $key_bc36 = { eb 44 [2] d9 66 [2] df 53 [2] f1 53 [2] ce 4f }

  condition:
    any of them
}