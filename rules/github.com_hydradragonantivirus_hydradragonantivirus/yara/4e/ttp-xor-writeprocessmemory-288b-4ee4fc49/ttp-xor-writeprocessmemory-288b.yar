rule TTP_XOR_WriteProcessMemory_288b {
  strings:
    $key_288b = { 7f f9 [2] 4d db [2] 4b ee [2] 65 ee [2] 5a f2 }

  condition:
    any of them
}