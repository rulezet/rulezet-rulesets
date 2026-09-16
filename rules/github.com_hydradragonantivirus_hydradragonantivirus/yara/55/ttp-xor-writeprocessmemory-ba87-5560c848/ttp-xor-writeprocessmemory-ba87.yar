rule TTP_XOR_WriteProcessMemory_ba87 {
  strings:
    $key_ba87 = { ed f5 [2] df d7 [2] d9 e2 [2] f7 e2 [2] c8 fe }

  condition:
    any of them
}