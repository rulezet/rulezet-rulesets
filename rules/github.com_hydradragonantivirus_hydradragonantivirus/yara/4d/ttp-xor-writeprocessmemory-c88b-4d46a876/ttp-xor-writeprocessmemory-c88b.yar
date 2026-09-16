rule TTP_XOR_WriteProcessMemory_c88b {
  strings:
    $key_c88b = { 9f f9 [2] ad db [2] ab ee [2] 85 ee [2] ba f2 }

  condition:
    any of them
}