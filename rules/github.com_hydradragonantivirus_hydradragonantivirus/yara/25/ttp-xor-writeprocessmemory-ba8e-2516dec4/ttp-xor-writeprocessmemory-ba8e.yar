rule TTP_XOR_WriteProcessMemory_ba8e {
  strings:
    $key_ba8e = { ed fc [2] df de [2] d9 eb [2] f7 eb [2] c8 f7 }

  condition:
    any of them
}