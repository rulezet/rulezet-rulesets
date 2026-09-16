rule TTP_XOR_WriteProcessMemory_ab05 {
  strings:
    $key_ab05 = { fc 77 [2] ce 55 [2] c8 60 [2] e6 60 [2] d9 7c }

  condition:
    any of them
}