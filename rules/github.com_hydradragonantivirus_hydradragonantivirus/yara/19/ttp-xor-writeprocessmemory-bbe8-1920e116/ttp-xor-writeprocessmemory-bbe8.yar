rule TTP_XOR_WriteProcessMemory_bbe8 {
  strings:
    $key_bbe8 = { ec 9a [2] de b8 [2] d8 8d [2] f6 8d [2] c9 91 }

  condition:
    any of them
}