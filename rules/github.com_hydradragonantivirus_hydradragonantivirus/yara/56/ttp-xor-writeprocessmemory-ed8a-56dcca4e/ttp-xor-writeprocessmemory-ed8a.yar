rule TTP_XOR_WriteProcessMemory_ed8a {
  strings:
    $key_ed8a = { ba f8 [2] 88 da [2] 8e ef [2] a0 ef [2] 9f f3 }

  condition:
    any of them
}