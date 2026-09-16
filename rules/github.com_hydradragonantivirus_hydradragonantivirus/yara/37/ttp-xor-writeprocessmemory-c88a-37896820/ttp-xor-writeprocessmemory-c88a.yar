rule TTP_XOR_WriteProcessMemory_c88a {
  strings:
    $key_c88a = { 9f f8 [2] ad da [2] ab ef [2] 85 ef [2] ba f3 }

  condition:
    any of them
}