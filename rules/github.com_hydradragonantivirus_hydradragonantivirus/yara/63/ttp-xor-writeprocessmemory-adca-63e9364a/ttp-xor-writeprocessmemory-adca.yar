rule TTP_XOR_WriteProcessMemory_adca {
  strings:
    $key_adca = { fa b8 [2] c8 9a [2] ce af [2] e0 af [2] df b3 }

  condition:
    any of them
}