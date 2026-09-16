rule TTP_XOR_WriteProcessMemory_bcca {
  strings:
    $key_bcca = { eb b8 [2] d9 9a [2] df af [2] f1 af [2] ce b3 }

  condition:
    any of them
}