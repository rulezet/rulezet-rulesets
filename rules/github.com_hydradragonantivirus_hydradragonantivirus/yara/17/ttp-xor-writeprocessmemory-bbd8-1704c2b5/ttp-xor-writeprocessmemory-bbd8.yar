rule TTP_XOR_WriteProcessMemory_bbd8 {
  strings:
    $key_bbd8 = { ec aa [2] de 88 [2] d8 bd [2] f6 bd [2] c9 a1 }

  condition:
    any of them
}