rule TTP_XOR_WriteProcessMemory_208b {
  strings:
    $key_208b = { 77 f9 [2] 45 db [2] 43 ee [2] 6d ee [2] 52 f2 }

  condition:
    any of them
}