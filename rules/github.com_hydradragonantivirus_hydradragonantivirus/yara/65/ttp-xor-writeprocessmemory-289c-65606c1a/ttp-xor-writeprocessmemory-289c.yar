rule TTP_XOR_WriteProcessMemory_289c {
  strings:
    $key_289c = { 7f ee [2] 4d cc [2] 4b f9 [2] 65 f9 [2] 5a e5 }

  condition:
    any of them
}